/**
 * ©AngelaMos | 2025
 * Application routing configuration
 */

import { createBrowserRouter } from 'react-router-dom';

/**
 * Placeholder components for routes
 */
const PlaceholderPage = ({ title }: { title: string }) => (
  <div
    style={{
      backgroundColor: '#000',
      color: '#fff',
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      fontFamily: 'system-ui, -apple-system, sans-serif',
      flexDirection: 'column',
      gap: '1rem',
    }}
  >
    <h1>{title}</h1>
    <p style={{ color: '#888' }}>Page coming soon...</p>
  </div>
);

export const router = createBrowserRouter([
  {
    path: '/',
    element: <PlaceholderPage title="Dashboard" />,
  },
  {
    path: '/login',
    element: <PlaceholderPage title="Login" />,
  },
  {
    path: '/register',
    element: <PlaceholderPage title="Register" />,
  },
  {
    path: '/scan',
    element: <PlaceholderPage title="New Scan" />,
  },
  {
    path: '/history',
    element: <PlaceholderPage title="Scan History" />,
  },
]);
