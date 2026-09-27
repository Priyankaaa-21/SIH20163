import json
import random
import os

def add_jitter(coord, max_jitter=0.05):
    # 0.05 degrees is roughly 5km (adds noise to obscure exact location)
    return round(coord + random.uniform(-max_jitter, max_jitter), 6)

def main():
    dataset_path = '../dataset/iaea_diif_db.json'
    safe_dataset_path = '../dataset/iaea_diif_db_safe.json'
    
    if not os.path.exists(dataset_path):
        print(f"Error: {dataset_path} not found.")
        return
        
    with open(dataset_path, 'r') as f:
        data = json.load(f)
        
    for facility in data.get('facilities', []):
        facility['lat'] = add_jitter(facility['lat'])
        facility['lon'] = add_jitter(facility['lon'])
        
    data['note'] = "Gamma irradiator facilities worldwide. Coordinates have been intentionally JITTERED (fuzzed) for security purposes."
        
    with open(safe_dataset_path, 'w') as f:
        json.dump(data, f, indent=2)
        
    print(f"Successfully generated safe dataset: {safe_dataset_path}")

if __name__ == "__main__":
    main()
