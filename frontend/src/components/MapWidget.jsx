import React, { useEffect, useState } from 'react';
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { getFacilities } from '../api';

// Fix the missing default marker icons in Leaflet when using Webpack/Vite
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png',
  iconUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png',
  shadowUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png',
});

// Custom glowing dot icon for high-tech look
const pulseIcon = L.divIcon({
  className: 'custom-pulse-icon',
  html: '<div class="pulse-dot"></div>',
  iconSize: [12, 12],
  iconAnchor: [6, 6]
});

const MapWidget = () => {
  const [facilities, setFacilities] = useState([]);

  useEffect(() => {
    getFacilities()
      .then(data => setFacilities(data))
      .catch(err => console.error("Error loading facilities for map:", err));
  }, []);

  return (
    <div className="glass-panel" style={{ marginTop: '1.5rem', marginBottom: '1.5rem', height: '400px', display: 'flex', flexDirection: 'column' }}>
      <h3 style={{ marginTop: 0, marginBottom: '1rem', color: 'var(--text-muted)' }}>Global Nuclear Facilities & Sensors</h3>
      <div style={{ flex: 1, borderRadius: '8px', overflow: 'hidden', background: '#0a0a0a' }}>
        <MapContainer 
          center={[20, 0]} 
          zoom={2} 
          minZoom={2}
          maxBounds={[[-90, -180], [90, 180]]}
          maxBoundsViscosity={1.0}
          style={{ height: '100%', width: '100%' }}
        >
          <TileLayer
            attribution='&copy; <a href="https://www.openstreetmap.org/">OpenStreetMap</a> contributors'
            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
            className="map-tiles"
            noWrap={true}
          />
          {facilities.map((facility, idx) => (
            <Marker key={idx} position={[facility.lat, facility.lon]} icon={pulseIcon}>
              <Popup>
                <div style={{ color: '#000' }}>
                  <strong>Facility ID:</strong> {facility.id}<br/>
                  <strong>Location:</strong> {facility.city}, {facility.country}
                </div>
              </Popup>
            </Marker>
          ))}
        </MapContainer>
      </div>
    </div>
  );
};

export default MapWidget;
