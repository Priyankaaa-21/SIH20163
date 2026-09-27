import json
import random

# List of regions/cities and base coordinates
regions = [
    {"city": "Oak Ridge", "country": "USA", "lat": 36.01, "lon": -84.26},
    {"city": "Los Alamos", "country": "USA", "lat": 35.88, "lon": -106.30},
    {"city": "Sellafield", "country": "UK", "lat": 54.42, "lon": -3.49},
    {"city": "La Hague", "country": "France", "lat": 49.67, "lon": -1.88},
    {"city": "Fukushima", "country": "Japan", "lat": 37.42, "lon": 141.03},
    {"city": "Chernobyl", "country": "Ukraine", "lat": 51.38, "lon": 30.09},
    {"city": "Bucha", "country": "Ukraine", "lat": 50.54, "lon": 30.21},
    {"city": "Seoul", "country": "South Korea", "lat": 37.56, "lon": 126.97},
    {"city": "Bushehr", "country": "Iran", "lat": 28.82, "lon": 50.88},
    {"city": "Natanz", "country": "Iran", "lat": 33.72, "lon": 51.72},
    {"city": "Richland", "country": "USA", "lat": 46.28, "lon": -119.28},
    {"city": "Bruce", "country": "Canada", "lat": 44.32, "lon": -81.59},
    {"city": "Tarapur", "country": "India", "lat": 19.82, "lon": 72.66},
    {"city": "Kudankulam", "country": "India", "lat": 8.16, "lon": 77.71},
    {"city": "Kola", "country": "Russia", "lat": 67.46, "lon": 32.47},
    {"city": "Novovoronezh", "country": "Russia", "lat": 51.27, "lon": 39.20},
    {"city": "Barakah", "country": "UAE", "lat": 23.96, "lon": 52.23},
    {"city": "Koeberg", "country": "South Africa", "lat": -33.67, "lon": 18.43},
    {"city": "Angra", "country": "Brazil", "lat": -23.00, "lon": -44.45},
    {"city": "Atucha", "country": "Argentina", "lat": -33.96, "lon": -59.20},
    {"city": "Forsmark", "country": "Sweden", "lat": 60.40, "lon": 18.16},
    {"city": "Olkiluoto", "country": "Finland", "lat": 61.23, "lon": 21.44},
    {"city": "Doel", "country": "Belgium", "lat": 51.32, "lon": 4.25},
    {"city": "Rovno", "country": "Ukraine", "lat": 51.32, "lon": 25.89},
    {"city": "Karachi", "country": "Pakistan", "lat": 24.86, "lon": 66.99},
    {"city": "Haiyang", "country": "China", "lat": 36.71, "lon": 121.28},
    {"city": "Tianwan", "country": "China", "lat": 34.68, "lon": 119.46},
    {"city": "Mochovce", "country": "Slovakia", "lat": 48.25, "lon": 18.45},
    {"city": "Paks", "country": "Hungary", "lat": 46.57, "lon": 18.85},
    {"city": "Cernavoda", "country": "Romania", "lat": 44.32, "lon": 28.05},
]

facilities = []
for i in range(1, 101):
    region = random.choice(regions)
    # Add significant jitter (up to ~50 miles) so they are spread out across the countries
    jitter_lat = random.uniform(-1.5, 1.5)
    jitter_lon = random.uniform(-1.5, 1.5)
    
    facilities.append({
        "id": f"gi-{i:03d}",
        "city": region["city"] + " (Region)",
        "country": region["country"],
        "lat": round(region["lat"] + jitter_lat, 4),
        "lon": round(region["lon"] + jitter_lon, 4)
    })

data = {
  "source": "IAEA DIIF - Database on Industrial Irradiation Facilities (Expanded Demo)",
  "extracted": "2026-09-27",
  "totalFacilities": len(facilities),
  "note": "Gamma irradiator facilities worldwide. Coordinates have been intentionally JITTERED (fuzzed) for security purposes.",
  "facilities": facilities
}

with open("dataset/iaea_diif_db_safe.json", "w") as f:
    json.dump(data, f, indent=2)

print("Generated 100 fuzzed facility locations for the map.")
