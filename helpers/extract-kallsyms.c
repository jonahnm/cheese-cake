#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <ctype.h>
#include <limits.h>
#include <stddef.h>

// Types for endianness handling
typedef enum {
    ENDIAN_UNKNOWN = 0,
    ENDIAN_LITTLE,
    ENDIAN_BIG
} Endianness;

typedef enum {
    LAYOUT_UNKNOWN = 0,
    LAYOUT_OLD,      // offsets -> relative_base -> num_syms -> names -> markers -> token_table
    LAYOUT_NEW_6_4   // names -> num_syms -> markers -> token_table -> token_index -> offsets -> relative_base
} KallsymsLayout;

// Configuration and state
typedef struct {
    uint8_t *data;
    size_t size;
    Endianness endian;
    KallsymsLayout layout;
    
    // Pointers to structures in data
    uint8_t *token_table;
    uint8_t *token_index; // Might be in data or allocated
    uint8_t *markers;
    uint8_t *names;
    uint8_t *num_syms_ptr;
    uint8_t *relative_base_ptr;
    uint8_t *offsets_ptr;

    // Parsed values
    uint32_t num_syms;
    uint64_t relative_base;
    
    // Allocated data
    uint16_t *built_token_index; // If we had to build it
    bool token_index_is_built;

} KallsymsContext;

// -----------------------------------------------------------------------------
// Helper Functions
// -----------------------------------------------------------------------------

void *memmem_custom(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen) {
    if (needlelen == 0) return (void *)haystack;
    if (haystacklen < needlelen) return NULL;
    const uint8_t *h = haystack;
    const uint8_t *n = needle;
    for (size_t i = 0; i <= haystacklen - needlelen; i++) {
        if (h[i] == n[0] && memcmp(&h[i], n, needlelen) == 0) {
            return (void *)&h[i];
        }
    }
    return NULL;
}

void *memmem_last(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen) {
    if (needlelen == 0) return (void *)haystack;
    if (haystacklen < needlelen) return NULL;
    const uint8_t *h = haystack;
    const uint8_t *n = needle;
    for (size_t i = haystacklen - needlelen; i != (size_t)-1; i--) { // check i loop condition carefully
        if (h[i] == n[0] && memcmp(&h[i], n, needlelen) == 0) {
            return (void *)&h[i];
        }
    }
    return NULL;
}

// Safe integer reading with endianness
uint16_t read_u16(const uint8_t *p, Endianness e) {
    if (e == ENDIAN_BIG) return (p[0] << 8) | p[1];
    return (p[1] << 8) | p[0]; // Default to little or unknown (we might assume little for initial checks)
}

uint32_t read_u32(const uint8_t *p, Endianness e) {
    if (e == ENDIAN_BIG) return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
    return (p[3] << 24) | (p[2] << 16) | (p[1] << 8) | p[0];
}

uint64_t read_u64(const uint8_t *p, Endianness e) {
    uint64_t v = 0;
    if (e == ENDIAN_BIG) {
        for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    } else {
        for (int i = 0; i < 8; i++) v |= ((uint64_t)p[i]) << (i * 8);
    }
    return v;
}

int32_t read_i32(const uint8_t *p, Endianness e) {
    return (int32_t)read_u32(p, e);
}

void *align_up(const void *p, size_t align) {
    uintptr_t addr = (uintptr_t)p;
    if (addr % align == 0) return (void *)p;
    return (void *)((addr + align - 1) & ~(align - 1));
}

void *align_down(const void *p, size_t align) {
     uintptr_t addr = (uintptr_t)p;
     return (void *)(addr & ~(align - 1));
}

// Align a file offset (not pointer)
size_t align_offset(size_t offset, size_t align) {
    if (offset % align == 0) return offset;
    return (offset + align - 1) & ~(align - 1);
}

// -----------------------------------------------------------------------------
// Core Logic
// -----------------------------------------------------------------------------

// 1. Find kallsyms_token_table
// Returns offset of pattern found + 1 (so 0 means not found)
size_t find_token_table(KallsymsContext *ctx, size_t start_offset) {
    if (start_offset >= ctx->size) return 0;

    // Search for pattern: 'A'\0'B'\0'C'\0...'Z'\0
    uint8_t pattern[26 * 2];
    for (int i = 0; i < 26; i++) {
        pattern[i * 2] = 'A' + i;
        pattern[i * 2 + 1] = 0;
    }

    uint8_t *found = memmem_custom(ctx->data + start_offset, ctx->size - start_offset, pattern, sizeof(pattern));
    if (!found) {
        return 0;
    }
    
    // Calculate pattern offset for return
    size_t pattern_offset = found - ctx->data;

    // Go backwards 0x41 (65) null-terminated strings
    uint8_t *curr = found;
    for (int i = 0; i < 0x41; i++) {
        // Start search from curr - 2
        uint8_t *p = curr - 2;
        while (p > ctx->data && *p != 0) {
            p--;
        }
        curr = p + 1;
    }
    
    ctx->token_table = (uint8_t*)align_up(curr, 4);
    
    return pattern_offset + 1;
}
// 2. Find/Build Token Index
int find_token_index(KallsymsContext *ctx) {
    // Reconstruct expected offsets
    uint16_t expected[256];
    uint32_t current_offset = 0;
    uint8_t *p = ctx->token_table;
    
    for (int i = 0; i < 256; i++) {
        expected[i] = (uint16_t)current_offset;
        size_t len = strlen((char*)p);
        current_offset += len + 1;
        p += len + 1;
    }
    
    // Build LE and BE byte patterns
    uint8_t pat_le[512];
    uint8_t pat_be[512];
    for (int i = 0; i < 256; i++) {
        pat_le[i*2] = expected[i] & 0xFF;
        pat_le[i*2+1] = (expected[i] >> 8) & 0xFF;
        pat_be[i*2] = (expected[i] >> 8) & 0xFF;
        pat_be[i*2+1] = expected[i] & 0xFF;
    }

    // Search for index in file (window after table)
    // Table ends at p.
    uint8_t *search_start = (uint8_t*)align_up(p, 8);
    // Search window size: 64KB
    // Use memmem to search for the pattern
    
    // Try Little Endian
    uint8_t *found = memmem_custom(search_start, 65536, pat_le, 512);
    if (found && (found <= ctx->data + ctx->size - 512)) {
         ctx->endian = ENDIAN_LITTLE;
         ctx->token_index = found;
         ctx->token_index_is_built = false;
         return 1;
    }
    
    // Try Big Endian
    found = memmem_custom(search_start, 65536, pat_be, 512);
    if (found && (found <= ctx->data + ctx->size - 512)) {
         ctx->endian = ENDIAN_BIG;
         ctx->token_index = found;
         ctx->token_index_is_built = false;
         return 1;
    }

    // Not found. Build it.
    ctx->built_token_index = malloc(256 * sizeof(uint16_t));
    // copy expected to built (host endian)
    for(int i=0; i<256; i++) ctx->built_token_index[i] = expected[i];
    ctx->token_index_is_built = true;
    
    // If we failed to find index, Endianness remains unknown/default.
    
    return 1;
}

// 3. Find markers
int find_markers(KallsymsContext *ctx) {
    // Search backwards from token table.
    // Pattern: `[0, val1, val2, ...]`
    
    uint8_t *p = (uint8_t*)align_down(ctx->token_table, 4);
    uint8_t *limit = p - 1024 * 1024;
    if (limit < ctx->data) limit = ctx->data;

    while (p > limit) {
        p -= 4;
        
        if (*(uint32_t*)p == 0) {
            // Potential start of markers?
            uint8_t *m = p;
            
            // Try Little Endian
            uint32_t v1_le = read_u32(m + 4, ENDIAN_LITTLE);
            uint32_t v2_le = read_u32(m + 8, ENDIAN_LITTLE);
            uint32_t v3_le = read_u32(m + 12, ENDIAN_LITTLE);
            
            bool match_le = (v1_le > 0x200 && v1_le < 0x40000 && 
                             v2_le > v1_le && (v2_le - v1_le) > 500 && (v2_le - v1_le) < 20000 &&
                             v3_le > v2_le && (v3_le - v2_le) > 500 && (v3_le - v2_le) < 20000);
            
            // Try Big Endian
            uint32_t v1_be = read_u32(m + 4, ENDIAN_BIG);
            uint32_t v2_be = read_u32(m + 8, ENDIAN_BIG);
            uint32_t v3_be = read_u32(m + 12, ENDIAN_BIG);
            
            bool match_be = (v1_be > 0x200 && v1_be < 0x40000 && 
                             v2_be > v1_be && (v2_be - v1_be) > 500 && (v2_be - v1_be) < 20000 &&
                             v3_be > v2_be && (v3_be - v2_be) > 500 && (v3_be - v2_be) < 20000);
            
            if (match_le) {
                if (ctx->endian == ENDIAN_UNKNOWN) ctx->endian = ENDIAN_LITTLE;
                if (ctx->endian == ENDIAN_LITTLE) {
                    ctx->markers = p;
                    return 1;
                }
            }
            
            if (match_be) {
                if (ctx->endian == ENDIAN_UNKNOWN) ctx->endian = ENDIAN_BIG;
                if (ctx->endian == ENDIAN_BIG) {
                    ctx->markers = p;
                    return 1;
                }
            }
        }
    }
    return 0;
}

// Helper to validate relative_base
bool check_relative_base(uint64_t rb) {
    return ((rb & 0xffff000000000000ULL) == 0xffff000000000000ULL || 
            (rb & 0xffffffff00000000ULL) == 0xc000000000000000ULL ||
            (rb == 0)); // 0 is unlikely but technically checking for high bits consistency
}

// 4. Find Names and Num Syms
int find_names_and_metadata(KallsymsContext *ctx) {
    
    // Common verification logic for a num_syms candidate
    // Returns 1 if valid, setting ctx fields.
    int try_verify(KallsymsContext *ctx, uint32_t ns, uint8_t *ns_ptr, uint8_t *names_ptr, Endianness try_e) {
        // 1. Check OLD Layout: relative_base is at ns_ptr - 8
        if (ns_ptr - 8 >= ctx->data) {
             uint64_t rb = read_u64(ns_ptr - 8, try_e);
             if (check_relative_base(rb)) {
                 ctx->num_syms = ns;
                 ctx->names = names_ptr;
                 ctx->num_syms_ptr = ns_ptr;
                 ctx->endian = try_e;
                 ctx->layout = LAYOUT_OLD;
                 ctx->relative_base = rb;
                 ctx->relative_base_ptr = ns_ptr - 8;
                 // offsets calculated later or now
                 size_t offsets_size = ((ns * 4) + 7) & ~7;
                 ctx->offsets_ptr = ctx->relative_base_ptr - offsets_size;
                 return 1;
             }
        }
        
        // 2. Check NEW Layout (Kernel 6.4+): relative_base is after offsets, which are after token_index
        // Requires token_index to be present in file
        if (ctx->token_index && !ctx->token_index_is_built) {
            // offsets start aligned after token_index
            // token_index size is 256 * 2 = 512
            uint8_t *idx_end = ctx->token_index + 512;
            
            // Alignment for offsets table. 
            // Python: position += -position % align_size. align_size is 4 or 8.
            // We assume 4-byte alignment for the start of the array is sufficient/standard.
            // But let's be precise: The file offset should be aligned.
            size_t idx_end_offset = idx_end - ctx->data;
            size_t offsets_start_offset = align_offset(idx_end_offset, 4);
            
            uint8_t *offsets_ptr = ctx->data + offsets_start_offset;
            
            if (offsets_ptr < ctx->data + ctx->size) {
                size_t offsets_len = ns * 4;
                uint8_t *offsets_end = offsets_ptr + offsets_len;
                
                // relative_base is aligned to 8 bytes (assuming 64-bit kernel)
                size_t offsets_end_offset = offsets_end - ctx->data;
                size_t rb_offset = align_offset(offsets_end_offset, 8); // Always 8 for relative_base
                
                uint8_t *rb_ptr = ctx->data + rb_offset;
                
                if (rb_ptr + 8 <= ctx->data + ctx->size) {
                    uint64_t rb = read_u64(rb_ptr, try_e);
                    if (check_relative_base(rb)) {
                         ctx->num_syms = ns;
                         ctx->names = names_ptr;
                         ctx->num_syms_ptr = ns_ptr;
                         ctx->endian = try_e;
                         ctx->layout = LAYOUT_NEW_6_4;
                         ctx->relative_base = rb;
                         ctx->relative_base_ptr = rb_ptr;
                         ctx->offsets_ptr = offsets_ptr;
                         return 1;
                    }
                }
            }
        }
        return 0;
    }

    // Method 1: Search backwards from markers for \0\0\0\0 padding
    if (ctx->markers) {
        uint32_t zero = 0;
        size_t search_len = ctx->markers - ctx->data;
        
        while (search_len > 0) {
            uint8_t *zeros = memmem_last(ctx->data, search_len, &zero, 4);
            if (!zeros) break;
            
            uint8_t *candidate_names = zeros + 4;
            uint8_t *ns_ptr = candidate_names - 8;
            
            if (ns_ptr >= ctx->data) {
                 uint32_t ns = read_u32(ns_ptr, ctx->endian);
                 if (ns > 10000 && ns < 2000000) {
                      ptrdiff_t name_len = ctx->markers - candidate_names;
                      if (name_len >= (ptrdiff_t)ns) {
                          if (try_verify(ctx, ns, ns_ptr, candidate_names, ctx->endian)) return 1;
                      }
                  }
             }            
            search_len = zeros - ctx->data;
        }
    }
    
    // Method 2: Search backwards from token_table for valid num_syms
    // This covers cases where markers were not found or Method 1 failed
    uint8_t *search_end = (uint8_t*)align_down(ctx->token_table, 4);
    while (search_end > ctx->data && *(search_end-1) == 0) search_end--;
    
    uint8_t *p = (uint8_t*)align_down(ctx->token_table, 8);
    uint8_t *limit = p - 30 * 1024 * 1024;
    if (limit < ctx->data) limit = ctx->data;
    
    for (; p > limit; p -= 4) {
        uint32_t ns = 0;
        Endianness try_e = ctx->endian;
        
        if (try_e == ENDIAN_UNKNOWN) {
             // Try Little
             ns = read_u32(p, ENDIAN_LITTLE);
             if (ns > 10000 && ns < 2000000) try_e = ENDIAN_LITTLE;
             else {
                 ns = read_u32(p, ENDIAN_BIG);
                 if (ns > 10000 && ns < 2000000) try_e = ENDIAN_BIG;
                 else continue;
             }
        } else {
            ns = read_u32(p, try_e);
            if (ns < 10000 || ns > 2000000) continue;
        }

        // Density Check
        if (search_end < (p + 8) || (search_end - (p + 8)) < (ptrdiff_t)ns) continue;
        
        // Parse loop to verify valid compressed stream
        uint8_t *name_ptr = p + 8;
        uint8_t *curr = name_ptr;
        bool ok = true;
        for (uint32_t i = 0; i < ns; i++) {
            if (curr >= ctx->token_table) { ok = false; break; }
            uint8_t len = *curr++;
            uint32_t count = len;
            if (len & 0x80) {
                if (curr >= ctx->token_table) { ok = false; break; }
                count = (len & 0x7f) | (*curr++ << 7);
            }
            curr += count;
        }
        
        if (ok) {
            // Relaxed check: curr must be <= token_table.
            if (curr <= ctx->token_table && curr > name_ptr) {
                 if (try_verify(ctx, ns, p, name_ptr, try_e)) return 1;
            }
        }
    }
    
    return 0;
}

// 5. Extract
void extract_symbols(KallsymsContext *ctx) {
    // Pointers and relative_base should already be set by verify_layout
    
    // Iterate and print
    uint8_t *name_p = ctx->names;
    FILE *out = fopen("kallsyms.txt", "w");
    if (!out) { perror("fopen"); exit(1); }
    
    printf("writing kallsyms.txt...\n");
    
    for (uint32_t i = 0; i < ctx->num_syms; i++) {
        // 1. Get Address
        int32_t offset = read_i32(ctx->offsets_ptr + i * 4, ctx->endian);
        uint64_t addr;
        if (offset < 0) {
            addr = ctx->relative_base - 1 - offset;
        } else {
            addr = ctx->relative_base + offset;
        }
        
        // 2. Decompress Name
        uint8_t count = *name_p++;
        if (count & 0x80) {
            count = (count & 0x7f) | (*name_p++ << 7);
        }
        
        char name_buf[512];
        char *dst = name_buf;
        
        for (int j = 0; j < count; j++) {
            uint8_t idx = *name_p++;
            // Get offset from index
            uint16_t tok_off;
            if (ctx->token_index_is_built) {
                tok_off = ctx->built_token_index[idx];
            } else {
                tok_off = read_u16(ctx->token_index + idx * 2, ctx->endian);
            }
            
            const char *tok = (const char *)(ctx->token_table + tok_off);
            size_t len = strlen(tok);
            if (dst - name_buf + len < sizeof(name_buf) - 1) {
                memcpy(dst, tok, len);
                dst += len;
            }
        }
        *dst = 0;
        
        // 3. Print
        if (strlen(name_buf) > 0) {
            char type = name_buf[0];
            char *name = name_buf + 1;
            fprintf(out, "%016lx %c %s\n", addr, type, name);
        }
    }
    
    fclose(out);
    printf("wrote kallsyms.txt\n");
}


int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <kernel_file>\n", argv[0]);
        return 1;
    }
    
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }
    
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    uint8_t *data = malloc(size);
    if (!data) { perror("malloc"); return 1; }
    if (fread(data, 1, size, f) != size) { perror("fread"); return 1; }
    fclose(f);
    
    KallsymsContext ctx = {0};
    ctx.data = data;
    ctx.size = size;
    ctx.endian = ENDIAN_UNKNOWN;
    
    size_t offset = 0;
    int found_count = 0;
    
    while (offset < ctx.size) {
        size_t next_offset = find_token_table(&ctx, offset);
        if (!next_offset) break;
        
        found_count++;
        
        // Reset context state for this attempt
        ctx.token_index = NULL;
        ctx.built_token_index = NULL;
        ctx.token_index_is_built = false;
        ctx.endian = ENDIAN_UNKNOWN;
        ctx.markers = NULL;
        ctx.num_syms = 0;
        ctx.names = NULL;
        ctx.num_syms_ptr = NULL;
        ctx.relative_base_ptr = NULL;
        ctx.offsets_ptr = NULL;
        ctx.layout = LAYOUT_UNKNOWN;
        
        // Step 2: Find Index
        find_token_index(&ctx);
        
        // Step 3: Find Markers
        find_markers(&ctx);
        
        // Step 4: Find Names
        if (find_names_and_metadata(&ctx)) {
             extract_symbols(&ctx);
             
             // Cleanup and exit success
             free(data);
             if (ctx.built_token_index) free(ctx.built_token_index);
             return 0;
        }
        
        // Cleanup for next iteration
        if (ctx.built_token_index) { free(ctx.built_token_index); ctx.built_token_index = NULL; }
        
        // Continue search after the PATTERN found
        offset = next_offset;
    }
    
    fprintf(stderr, "Failed to find valid kallsyms in %d candidates.\n", found_count);
    
    free(data);
    
    return 1;
}
