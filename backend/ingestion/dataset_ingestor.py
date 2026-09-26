import os
import json
from typing import Dict, Any

class DatasetIngestor:
    def __init__(self, dataset_path: str):
        self.dataset_path = dataset_path

    def load_dataset(self) -> Dict[str, Any]:
        """Loads all JSON files from the dataset directory into a dictionary."""
        loaded_data = {}
        if not os.path.exists(self.dataset_path):
            print(f"Warning: Dataset path {self.dataset_path} does not exist.")
            return loaded_data

        for filename in os.listdir(self.dataset_path):
            if filename.endswith(".json"):
                file_path = os.path.join(self.dataset_path, filename)
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        key = filename.replace(".json", "")
                        loaded_data[key] = json.load(f)
                except Exception as e:
                    print(f"Error loading {filename}: {e}")
        
        return loaded_data
