import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { CssBaseline, Box } from '@mui/material';
import { QueryClient, QueryClientProvider } from 'react-query';
import { Toaster } from 'react-hot-toast';

// Components
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import Dashboard from './pages/Dashboard';
import ScanManagement from './pages/ScanManagement';
import IBBResearch from './pages/IBBResearch';
import MLIntelligence from './pages/MLIntelligence';
import VulnerabilityDatabase from './pages/VulnerabilityDatabase';
import Reports from './pages/Reports';
import Settings from './pages/Settings';
import ScanDetails from './pages/ScanDetails';

// Theme configuration
const darkTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#00ff88',
      dark: '#00cc6a',
      light: '#4dffaa',
    },
    secondary: {
      main: '#ff4444',
      dark: '#cc0000',
      light: '#ff7777',
    },
    background: {
      default: '#0a0a0a',
      paper: '#1a1a1a',
    },
    text: {
      primary: '#ffffff',
      secondary: '#cccccc',
    },
  },
  typography: {
    fontFamily: '"Roboto Mono", "Courier New", monospace',
    h1: {
      fontSize: '2.5rem',
      fontWeight: 700,
      color: '#00ff88',
    },
    h2: {
      fontSize: '2rem',
      fontWeight: 600,
      color: '#00ff88',
    },
    h3: {
      fontSize: '1.5rem',
      fontWeight: 500,
    },
  },
  components: {
    MuiCard: {
      styleOverrides: {
        root: {
          backgroundColor: '#1a1a1a',
          border: '1px solid #333',
          '&:hover': {
            border: '1px solid #00ff88',
          },
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          textTransform: 'none',
          fontWeight: 600,
        },
        contained: {
          background: 'linear-gradient(45deg, #00ff88 30%, #00cc6a 90%)',
          '&:hover': {
            background: 'linear-gradient(45deg, #00cc6a 30%, #009944 90%)',
          },
        },
      },
    },
  },
});

// Create query client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 30000,
    },
  },
});

const App: React.FC = () => {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider theme={darkTheme}>
        <CssBaseline />
        <Router>
          <Box sx={{ display: 'flex', minHeight: '100vh' }}>
            <Sidebar />
            <Box sx={{ flexGrow: 1, display: 'flex', flexDirection: 'column' }}>
              <Header />
              <Box component="main" sx={{ flexGrow: 1, p: 3, backgroundColor: '#0a0a0a' }}>
                <Routes>
                  <Route path="/" element={<Dashboard />} />
                  <Route path="/scans" element={<ScanManagement />} />
                  <Route path="/scans/:scanId" element={<ScanDetails />} />
                  <Route path="/ibb-research" element={<IBBResearch />} />
                  <Route path="/ml-intelligence" element={<MLIntelligence />} />
                  <Route path="/vulnerabilities" element={<VulnerabilityDatabase />} />
                  <Route path="/reports" element={<Reports />} />
                  <Route path="/settings" element={<Settings />} />
                </Routes>
              </Box>
            </Box>
          </Box>
        </Router>
        <Toaster
          position="top-right"
          toastOptions={{
            duration: 4000,
            style: {
              background: '#1a1a1a',
              color: '#ffffff',
              border: '1px solid #00ff88',
            },
          }}
        />
      </ThemeProvider>
    </QueryClientProvider>
  );
};

export default App;