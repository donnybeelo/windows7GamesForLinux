import os
import sys
import glob
import lief

def get_node_key(node):
    if node.has_name:
        return ("name", node.name)
    else:
        return ("id", node.id)

def find_child(parent, key):
    # parent.childs is an iterator/list-like access
    for child in parent.childs:
        if get_node_key(child) == key:
            return child
    return None

def copy_nodes(target_parent, source_node):
    # source_node is a ResourceDirectory (or Root)
    # We iterate its children
    source_children = list(source_node.childs)
    
    for child in source_children:
        key = get_node_key(child)
        existing = find_child(target_parent, key)
        
        if isinstance(child, lief.PE.ResourceData):
            # Leaf node (Data)
            if existing:
                target_parent.delete_child(existing)
            
            # Create new Data node
            new_data = lief.PE.ResourceData(child.content)
            if key[0] == "name":
                new_data.name = key[1]
            else:
                new_data.id = key[1]
            
            target_parent.add_child(new_data)
            
        elif isinstance(child, lief.PE.ResourceDirectory):
            # Directory node
            target_child = existing
            
            if not target_child:
                # Create it
                # For named directory, we can pass any ID (e.g. 0) and set name
                # For ID directory, we pass the ID
                if key[0] == "name":
                    new_node = lief.PE.ResourceDirectory(0)
                    new_node.name = key[1]
                else:
                    new_node = lief.PE.ResourceDirectory(key[1])
                
                target_child = target_parent.add_child(new_node)
            
            # Recurse
            copy_nodes(target_child, child)

def copy_resources(target_exe_path, source_mui_path):
    print(f"  Patching {os.path.basename(target_exe_path)} with {os.path.basename(source_mui_path)}...")
    try:
        binary = lief.PE.parse(target_exe_path)
        mui = lief.PE.parse(source_mui_path)
    except Exception as e:
        print(f"  Error parsing files: {e}")
        return False

    if not binary.resources:
        print("  Target has no resources, creating root...")
        binary.resources = lief.PE.ResourceDirectory(0)
    
    if not mui.resources:
        print("  MUI has no resources.")
        return False

    try:
        copy_nodes(binary.resources, mui.resources)
        
        # Configure Builder
        config = lief.PE.Builder.config_t()
        config.resources = True
        
        builder = lief.PE.Builder(binary, config)
        builder.build()
        
        tmp_output = target_exe_path + ".tmp"
        builder.write(tmp_output)
        
        # Replace original
        os.replace(tmp_output, target_exe_path)
        print("  Success.")
        return True
    except Exception as e:
        print(f"  Error during patching: {e}")
        return False

def main(prefix_path):
    drive_c = os.path.join(prefix_path, "drive_c")
    search_paths = [
        os.path.join(drive_c, "Program Files", "Microsoft Games"),
        os.path.join(drive_c, "Program Files (x86)", "Microsoft Games")
    ]
    
    games_root = None
    for p in search_paths:
        if os.path.exists(p):
            games_root = p
            break
            
    if not games_root:
        print("Could not find Microsoft Games installation directory.")
        return

    print(f"Found games in: {games_root}")
    
    for game_dir in glob.glob(os.path.join(games_root, "*")):
        if not os.path.isdir(game_dir):
            continue
            
        game_name = os.path.basename(game_dir)
        print(f"Processing {game_name}...")
        
        exes = glob.glob(os.path.join(game_dir, "*.exe"))
        if not exes:
            print(f"  No EXE found in {game_dir}")
            continue
        
        for exe_path in exes:
            exe_name = os.path.basename(exe_path)
            
            # Look for MUI in en-US
            mui_path = os.path.join(game_dir, "en-US", f"{exe_name}.mui")
            if not os.path.exists(mui_path):
                # Try en_US just in case
                mui_path = os.path.join(game_dir, "en_US", f"{exe_name}.mui")
                
            if not os.path.exists(mui_path):
                print(f"  No MUI found for {exe_name}")
                continue
                
            copy_resources(exe_path, mui_path)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: patcher_lief.py <wine_prefix>")
        sys.exit(1)
    main(sys.argv[1])