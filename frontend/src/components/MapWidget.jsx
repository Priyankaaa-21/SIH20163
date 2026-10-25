import React, { useEffect, useState } from 'react';
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { getFacilities } from '../api';
import { MapPin, AlertCircle } from 'lucide-react';

// Self-host Leaflet marker icons from public folder without unpkg external dependencies
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: '/marker-icon-2x.png',
  iconUrl: '/marker-icon.png',
  shadowUrl: '/marker-shadow.png',
});

// Clean custom marker icon
const customMarker = L.divIcon({
  className: 'custom-map-marker',
  html: '<div style="width: 10px; height: 10px; background-color: #2563eb; border: 2px solid #ffffff; border-radius: 50%;"></div>',
  iconSize: [10, 10],
  iconAnchor: [5, 5]
});

const MapWidget = () => {
  const [facilities, setFacilities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let isMounted = true;
    getFacilities()
      .then(data => {
        if (isMounted) {
          setFacilities(Array.isArray(data) ? data : []);
          setLoading(false);
        }
      })
      .catch(() => {
        if (isMounted) {
          setError('Failed to load facility locations.');
          setLoading(false);
        }
      });
    return () => { isMounted = false; };
  }, []);

  return (
    <div className="panel map-card">
      <div className="map-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
          <MapPin size={18} color="var(--accent-light)" />
          <h2 style={{ margin: 0, fontSize: 'var(--text-base)', fontWeight: 600, color: 'var(--text-primary)' }}>
            Critical Infrastructure & Sensor Locations
          </h2>
        </div>
        <div className="map-legend">
          Synthetic demo data
        </div>
      </div>

      <div style={{ flex: 1, position: 'relative', borderRadius: 'var(--radius)', overflow: 'hidden', minHeight: '280px' }}>
        {loading && (
          <div className="state-box" style={{ height: '100%' }}>
            <div className="skeleton-line" style={{ width: '60%' }}></div>
            <div>Loading facilities map...</div>
          </div>
        )}

        {error && (
          <div className="state-box" style={{ height: '100%', color: '#fca5a5' }}>
            <AlertCircle size={24} />
            <div>{error}</div>
          </div>
        )}

        {!loading && !error && (
          <MapContainer 
            center={[20, 0]} 
            zoom={2} 
            minZoom={2}
            maxBounds={[[-90, -180], [90, 180]]}
            maxBoundsViscosity={1.0}
            style={{ height: '100%', width: '100%', borderRadius: 'var(--radius)' }}
          >
            <TileLayer
              attribution='&copy; <a href="https://www.openstreetmap.org/">OpenStreetMap</a> contributors'
              url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
              className="map-dark-tiles"
              noWrap={true}
            />
            {facilities.map((fac, idx) => (
              <Marker key={idx} position={[fac.lat, fac.lon]} icon={customMarker}>
                <Popup>
                  <div style={{ color: '#111827', fontSize: '13px' }}>
                    <strong>Facility ID:</strong> {fac.id}<br/>
                    <strong>Location:</strong> {fac.city}, {fac.country}<br/>
                    <strong>Coordinates:</strong> {fac.lat}, {fac.lon}<br/>
                    <em style={{ color: '#4b5563', fontSize: '11px' }}>{fac.precision || 'Synthetic demo data'}</em>
                  </div>
                </Popup>
              </Marker>
            ))}
          </MapContainer>
        )}
      </div>
    </div>
  );
};

export default MapWidget;
