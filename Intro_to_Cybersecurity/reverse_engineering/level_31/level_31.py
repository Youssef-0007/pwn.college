import struct
import re
from collections import defaultdict, namedtuple
from pathlib import Path

# Config
IMG_WIDTH = 76
IMG_HEIGHT = 24
DESIRED_OUTPUT_PATH = "desired_output.txt"
OUTPUT_CIMG_PATH = "ultra_optimized_flag.cimg"

# Types
Pixel = namedtuple("Pixel", ["x", "y", "r", "g", "b", "char"])
Directive = namedtuple("Directive", ["code", "payload"])

# Globals
directives = []
total_bytes_sent = 0

def parse_desired_output(file_path):
    ansi_pattern = re.compile(r"\x1b\[38;2;(\d+);(\d+);(\d+)m(.)\x1b\[0m")
    pixels = []
    x, y = 0, 0
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
        for match in ansi_pattern.finditer(content):
            r, g, b, ch = match.groups()
            pixels.append(Pixel(x, y, int(r), int(g), int(b), ch))
            x += 1
            if x == IMG_WIDTH:
                x = 0
                y += 1
    return pixels

def create_region_sprites(pixels):
    """Create large rectangular sprites covering entire regions"""
    pixel_grid = {}
    for p in pixels:
        pixel_grid[(p.x, p.y)] = p
    
    sprites = {}
    sprite_usages = []
    sprite_id = 0
    used_pixels = set()
    
    # Strategy 1: Create one massive sprite for the entire border (white characters)
    top_patch = []
    bottom_patch = []
    left_patch = []
    right_patch = []
    
    for px in pixels:
        if (1 <= px.x <= 74 and px.y == 0):
            top_patch.append(px)
        elif (1 <= px.x <= 74 and px.y == 23):
            bottom_patch.append(px)
        elif (0 <= px.y <= 23 and px.x == 0):
            left_patch.append(px)
        elif (0 <= px.y <= 23 and px.x == 75):
            right_patch.append(px)
    borders_patches = []
    border_patches = [top_patch] + [bottom_patch] + [left_patch] + [right_patch]
    
    
    for patch in border_patches:
        # Determine if group is horizontal or vertical
        same_x = len(set(p.x for p in patch)) == 1
        same_y = len(set(p.y for p in patch)) == 1
    
        if same_y:  # Horizontal group
            w, h = len(patch), 1
        else:       # Vertical group
            w, h = 1, len(patch)        
         
        # create sprite key from char sequence only
        char_sequence = ''.join(p.char for p in patch)
        sprite_key = (w, h, char_sequence)
        
        if sprite_key not in sprites:
            sprites[sprite_key] = sprite_id
            sprite_id += 1
        
        # create usgae with position and color
        first_pixel = patch[0]
        sprite_usages.append({
            'sprite_id': sprites[sprite_key],
            'x': first_pixel.x,
            'y': first_pixel.y,
            'r': first_pixel.r,
            'g': first_pixel.g,
            'b': first_pixel.b
        })
    
    # Strategy 2: Group remaining pixels by color and create rectangular regions
    # Filter non-space pixels and create a grid
    pixels = [p for p in pixels if p.char != ' ' and (0 < p.x < 75) and (0 < p.y < 23)]
    remaining_pixels = [p for p in pixels if (p.x, p.y) not in used_pixels]
    color_groups = defaultdict(list)
    
    for p in remaining_pixels:
        color_key = (p.r, p.g, p.b)
        color_groups[color_key].append(p)
    
    for (r, g, b), color_pixels in color_groups.items():
        if not color_pixels:
            continue
        
        print(f"for the rgb : {r}, {g}, {b}")   
        # Find bounding rectangle for this color group
        min_x = min(p.x for p in color_pixels)
        max_x = max(p.x for p in color_pixels)
        min_y = min(p.y for p in color_pixels)
        max_y = max(p.y for p in color_pixels)
        print(f"bounding rectangle: {min_x}, {max_x}, {min_y}, {max_y}")
        region_width = max_x - min_x + 1
        region_height = max_y - min_y + 1
        print(f"dimensions --> width : {region_width}, height: {region_height}")
        # If the region is small or has good density, create a composite sprite
        total_area = region_width * region_height
        print(f"total area: {total_area}")
        pixel_count = len(color_pixels)
        print(f"pixel_count: {pixel_count}")
        density = pixel_count / total_area
        
        if total_area <= 50 or density >= 0.3:  # Good density or small region
            sprite_data = ""
            pixels_in_sprite = set()
            
            for y in range(min_y, max_y + 1):
                for x in range(min_x, max_x + 1):
                    if (x, y) in pixel_grid and pixel_grid[(x, y)] in color_pixels:
                        sprite_data += pixel_grid[(x, y)].char
                        pixels_in_sprite.add((x, y))
                    else:
                        sprite_data += " "
            
            if sprite_data.strip():
                sprite_key = (region_width, region_height, sprite_data)
                sprites[sprite_key] = sprite_id
                sprite_id += 1
                
                sprite_usages.append({
                    'sprite_id': sprites[sprite_key],
                    'x': min_x, 'y': min_y,
                    'r': r, 'g': g, 'b': b
                })
                
                used_pixels.update(pixels_in_sprite)
        else:
            # For sparse regions, try to create line sprites
            # Group by character type
            char_groups = defaultdict(list)
            for p in color_pixels:
                char_groups[p.char].append(p)
            
            for char, char_pixels in char_groups.items():
                # Try horizontal grouping first
                rows = defaultdict(list)
                for p in char_pixels:
                    if (p.x, p.y) not in used_pixels:
                        rows[p.y].append(p)
                
                for y, row_pixels in rows.items():
                    row_pixels.sort(key=lambda p: p.x)
                    
                    # Create line sprites for consecutive sequences
                    i = 0
                    while i < len(row_pixels):
                        start_x = row_pixels[i].x
                        width = 1
                        
                        # Extend sequence
                        while (i + width < len(row_pixels) and 
                               row_pixels[i + width].x == start_x + width):
                            width += 1
                        
                        if width >= 2:  # Create sprite for sequences of 2+
                            sprite_key = (width, 1, char * width)
                            if sprite_key not in sprites:
                                sprites[sprite_key] = sprite_id
                                sprite_id += 1
                            
                            sprite_usages.append({
                                'sprite_id': sprites[sprite_key],
                                'x': start_x, 'y': y,
                                'r': r, 'g': g, 'b': b
                            })
                            
                            # Mark pixels as used
                            for j in range(width):
                                used_pixels.add((start_x + j, y))
                            
                            i += width
                        else:
                            i += 1
    
    # Handle remaining individual pixels
    remaining = [p for p in pixels if (p.x, p.y) not in used_pixels]
    single_sprites = {}
    
    for p in remaining:
        sprite_key = (1, 1, p.char)
        if sprite_key not in single_sprites:
            single_sprites[sprite_key] = sprite_id
            sprite_id += 1
        
        sprite_usages.append({
            'sprite_id': single_sprites[sprite_key],
            'x': p.x, 'y': p.y,
            'r': p.r, 'g': p.g, 'b': p.b
        })
    
    sprites.update(single_sprites)
    return sprites, sprite_usages

def build_directives(sprite_table, sprite_usages):
    global total_bytes_sent, directives
    
    directives = []
    total_bytes_sent = 0
    
    # handle_3: sprite definitions
    for (w, h, char_data), sprite_id in sprite_table.items():
        directives.append(Directive(3, None))
        total_bytes_sent += 2
        
        sprite_data = struct.pack("BBB", sprite_id, w, h)
        total_bytes_sent += 3
        
        # Encode character data
        char_bytes = char_data.encode('ascii', errors='replace')
        sprite_data += char_bytes
        total_bytes_sent += len(char_bytes)
        
        directives.append(Directive(None, sprite_data))
    
    # handle_4: sprite placements
    for usage in sprite_usages:
        directives.append(Directive(4, None))
        total_bytes_sent += 2
        
        render_data = struct.pack("BBBBBB", 
                                usage['sprite_id'], 
                                usage['r'], 
                                usage['g'], 
                                usage['b'], 
                                usage['x'], 
                                usage['y'])
        directives.append(Directive(None, render_data))
        total_bytes_sent += 6

def write_cimg_file(path, directives_count):
    header = (
        b"cIMG" +
        struct.pack("<H", 3) +
        struct.pack("B", IMG_WIDTH) +
        struct.pack("B", IMG_HEIGHT) +
        struct.pack("<I", directives_count)
    )
    
    with open(path, "wb") as f:
        f.write(header)
        for directive in directives:
            if directive.code is not None:
                f.write(struct.pack("<H", directive.code))
            else:
                f.write(directive.payload)

def main():
    # Parse input
    pixels = parse_desired_output(DESIRED_OUTPUT_PATH)
    print(f"Total pixels parsed: {len(pixels)}")
    non_space = [p for p in pixels if p.char != ' ']
    print(f"Non-space pixels: {len(non_space)}")
    
    # Analyze color distribution
    color_counts = defaultdict(int)
    for p in non_space:
        color_counts[(p.r, p.g, p.b)] += 1
    
    print("\nColor analysis:")
    for color, count in sorted(color_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"RGB{color}: {count} pixels")
    
    # Create region-based sprites
    sprite_table, sprite_usages = create_region_sprites(pixels)
    
    # Build directives
    build_directives(sprite_table, sprite_usages)
    
    # Calculate total directives
    directives_count = len(sprite_table) + len(sprite_usages)
    
    # Write file
    write_cimg_file(OUTPUT_CIMG_PATH, directives_count)
    
    # Report results
    print(f"\n=== RESULTS ===")
    print(f"Sprite count: {len(sprite_table)}")
    print(f"Placement count: {len(sprite_usages)}")
    print(f"Total directives: {directives_count}")
    print(f"Total bytes sent: {total_bytes_sent}")
    print(f"Within limit: {'✅ YES' if total_bytes_sent <= 400 else '❌ NO'}")
    
    if total_bytes_sent > 400:
        print(f"Need to reduce by: {total_bytes_sent - 400} bytes")
    
    # Show sprite details
    print(f"\n=== SPRITE BREAKDOWN ===")
    total_sprite_bytes = 0
    total_usage_bytes = 0
    
    for (w, h, data), sid in sorted(sprite_table.items(), key=lambda x: len(x[0][2]), reverse=True):
        char_len = len(data)
        bytes_for_sprite = 2 + 3 + char_len
        total_sprite_bytes += bytes_for_sprite
        
        # Show sprite preview
        if char_len <= 50:
            display_data = repr(data)
        else:
            display_data = repr(data[:47]) + "..."
            
        print(f"Sprite {sid}: {w}x{h}, {display_data}, {bytes_for_sprite} bytes")
    
    total_usage_bytes = len(sprite_usages) * 8
    print(f"\nBytes breakdown:")
    print(f"Header: 12 bytes")
    print(f"Sprite definitions: {total_sprite_bytes} bytes")
    print(f"Sprite usages: {total_usage_bytes} bytes")
    print(f"Total payload: {total_sprite_bytes + total_usage_bytes} bytes")

if __name__ == "__main__":
    main()
