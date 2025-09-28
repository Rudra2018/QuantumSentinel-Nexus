import React, { useState, useEffect } from 'react';
import {
  Grid,
  Card,
  CardContent,
  Typography,
  Box,
  LinearProgress,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  IconButton,
  Tooltip,
} from '@mui/material';
import {
  Security,
  BugReport,
  Speed,
  TrendingUp,
  Visibility,
  PlayArrow,
  Stop,
  Refresh,
} from '@mui/icons-material';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { useQuery } from 'react-query';
import toast from 'react-hot-toast';

// API functions
import { fetchDashboardStats, fetchRecentScans, fetchVulnerabilityTrends } from '../api/api';

interface DashboardStats {
  totalScans: number;
  activeScans: number;
  criticalVulnerabilities: number;
  zeroDayPredictions: number;
  ibbFindings: number;
  mlPredictions: number;
}

interface RecentScan {
  id: string;
  type: string;
  target: string;
  status: string;
  findings: number;
  startedAt: string;
  completedAt: string | null;
}

const Dashboard: React.FC = () => {
  const [realTimeData, setRealTimeData] = useState<any>(null);

  // Queries
  const { data: stats, isLoading: statsLoading } = useQuery<DashboardStats>(
    'dashboardStats',
    fetchDashboardStats,
    { refetchInterval: 30000 }
  );

  const { data: recentScans, isLoading: scansLoading } = useQuery<RecentScan[]>(
    'recentScans',
    fetchRecentScans,
    { refetchInterval: 10000 }
  );

  const { data: vulnerabilityTrends } = useQuery(
    'vulnerabilityTrends',
    fetchVulnerabilityTrends,
    { refetchInterval: 60000 }
  );

  // WebSocket connection for real-time updates
  useEffect(() => {
    const ws = new WebSocket(process.env.REACT_APP_WEBSOCKET_URL || 'ws://localhost:8000/ws');

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      setRealTimeData(data);

      if (data.type === 'scan_completed') {
        toast.success(`Scan ${data.scanId} completed with ${data.findings} findings`);
      } else if (data.type === 'critical_vulnerability') {
        toast.error(`Critical vulnerability detected: ${data.description}`);
      }
    };

    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
    };

    return () => {
      ws.close();
    };
  }, []);

  const StatCard: React.FC<{
    title: string;
    value: number;
    icon: React.ReactNode;
    color: string;
    change?: number;
  }> = ({ title, value, icon, color, change }) => (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Box>
            <Typography color="textSecondary" gutterBottom variant="h6">
              {title}
            </Typography>
            <Typography variant="h4" sx={{ color, fontWeight: 'bold' }}>
              {value.toLocaleString()}
            </Typography>
            {change !== undefined && (
              <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
                <TrendingUp sx={{ fontSize: 16, mr: 0.5, color: change > 0 ? '#4caf50' : '#f44336' }} />
                <Typography
                  variant="body2"
                  sx={{ color: change > 0 ? '#4caf50' : '#f44336' }}
                >
                  {change > 0 ? '+' : ''}{change}% from last week
                </Typography>
              </Box>
            )}
          </Box>
          <Box sx={{ color, opacity: 0.7 }}>
            {icon}
          </Box>
        </Box>
      </CardContent>
    </Card>
  );

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return '#4caf50';
      case 'running': return '#ff9800';
      case 'failed': return '#f44336';
      case 'queued': return '#2196f3';
      default: return '#757575';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'running': return <PlayArrow sx={{ fontSize: 16 }} />;
      case 'completed': return <Stop sx={{ fontSize: 16 }} />;
      default: return null;
    }
  };

  const vulnerabilityData = [
    { name: 'Critical', value: 15, color: '#f44336' },
    { name: 'High', value: 32, color: '#ff9800' },
    { name: 'Medium', value: 67, color: '#ffc107' },
    { name: 'Low', value: 89, color: '#4caf50' },
  ];

  if (statsLoading) {
    return (
      <Box sx={{ width: '100%', mt: 2 }}>
        <LinearProgress />
      </Box>
    );
  }

  return (
    <Box>
      <Typography variant="h1" gutterBottom>
        QuantumSentinel-Nexus
      </Typography>
      <Typography variant="h6" color="textSecondary" gutterBottom>
        Enterprise Security Research Platform Dashboard
      </Typography>

      {/* Stats Cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={2}>
          <StatCard
            title="Total Scans"
            value={stats?.totalScans || 0}
            icon={<Security sx={{ fontSize: 40 }} />}
            color="#00ff88"
            change={12}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={2}>
          <StatCard
            title="Active Scans"
            value={stats?.activeScans || 0}
            icon={<Speed sx={{ fontSize: 40 }} />}
            color="#ff9800"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={2}>
          <StatCard
            title="Critical Vulns"
            value={stats?.criticalVulnerabilities || 0}
            icon={<BugReport sx={{ fontSize: 40 }} />}
            color="#f44336"
            change={-8}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={2}>
          <StatCard
            title="Zero-Day Predictions"
            value={stats?.zeroDayPredictions || 0}
            icon={<TrendingUp sx={{ fontSize: 40 }} />}
            color="#9c27b0"
            change={25}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={2}>
          <StatCard
            title="IBB Findings"
            value={stats?.ibbFindings || 0}
            icon={<Visibility sx={{ fontSize: 40 }} />}
            color="#2196f3"
            change={18}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={2}>
          <StatCard
            title="ML Predictions"
            value={stats?.mlPredictions || 0}
            icon={<Speed sx={{ fontSize: 40 }} />}
            color="#00bcd4"
            change={34}
          />
        </Grid>
      </Grid>

      <Grid container spacing={3}>
        {/* Vulnerability Trends Chart */}
        <Grid item xs={12} lg={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Vulnerability Discovery Trends
              </Typography>
              <Box sx={{ height: 300 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={vulnerabilityTrends}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                    <XAxis dataKey="date" stroke="#ccc" />
                    <YAxis stroke="#ccc" />
                    <Line
                      type="monotone"
                      dataKey="critical"
                      stroke="#f44336"
                      strokeWidth={2}
                      name="Critical"
                    />
                    <Line
                      type="monotone"
                      dataKey="high"
                      stroke="#ff9800"
                      strokeWidth={2}
                      name="High"
                    />
                    <Line
                      type="monotone"
                      dataKey="medium"
                      stroke="#ffc107"
                      strokeWidth={2}
                      name="Medium"
                    />
                  </LineChart>
                </ResponsiveContainer>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* Vulnerability Distribution */}
        <Grid item xs={12} lg={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Vulnerability Distribution
              </Typography>
              <Box sx={{ height: 300 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={vulnerabilityData}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={100}
                      paddingAngle={5}
                      dataKey="value"
                    >
                      {vulnerabilityData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>
              </Box>
              <Box sx={{ mt: 2 }}>
                {vulnerabilityData.map((item) => (
                  <Box key={item.name} sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    <Box
                      sx={{
                        width: 16,
                        height: 16,
                        backgroundColor: item.color,
                        borderRadius: 1,
                        mr: 1,
                      }}
                    />
                    <Typography variant="body2">
                      {item.name}: {item.value}
                    </Typography>
                  </Box>
                ))}
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* Recent Scans */}
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'between', mb: 2 }}>
                <Typography variant="h6">
                  Recent Scans
                </Typography>
                <Tooltip title="Refresh">
                  <IconButton>
                    <Refresh />
                  </IconButton>
                </Tooltip>
              </Box>
              <TableContainer component={Paper} sx={{ backgroundColor: 'transparent' }}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Scan ID</TableCell>
                      <TableCell>Type</TableCell>
                      <TableCell>Target</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>Findings</TableCell>
                      <TableCell>Started</TableCell>
                      <TableCell>Duration</TableCell>
                      <TableCell>Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {recentScans?.map((scan) => (
                      <TableRow key={scan.id} hover>
                        <TableCell>
                          <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                            {scan.id.substring(0, 8)}...
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={scan.type}
                            size="small"
                            variant="outlined"
                            sx={{ textTransform: 'capitalize' }}
                          />
                        </TableCell>
                        <TableCell>{scan.target}</TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', alignItems: 'center' }}>
                            {getStatusIcon(scan.status)}
                            <Chip
                              label={scan.status}
                              size="small"
                              sx={{
                                backgroundColor: getStatusColor(scan.status),
                                color: 'white',
                                ml: 1,
                              }}
                            />
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Typography
                            variant="body2"
                            sx={{
                              color: scan.findings > 0 ? '#f44336' : '#4caf50',
                              fontWeight: 'bold',
                            }}
                          >
                            {scan.findings}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2">
                            {new Date(scan.startedAt).toLocaleString()}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2">
                            {scan.completedAt
                              ? Math.round(
                                  (new Date(scan.completedAt).getTime() -
                                    new Date(scan.startedAt).getTime()) /
                                    60000
                                ) + ' min'
                              : 'Running...'}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Tooltip title="View Details">
                            <IconButton size="small">
                              <Visibility sx={{ fontSize: 18 }} />
                            </IconButton>
                          </Tooltip>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </CardContent>
          </Card>
        </Grid>

        {/* Live Activity Feed */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Live Activity Feed
              </Typography>
              <Box sx={{ maxHeight: 300, overflow: 'auto' }}>
                {realTimeData && (
                  <Box sx={{ mb: 1, p: 1, backgroundColor: '#333', borderRadius: 1 }}>
                    <Typography variant="body2" sx={{ color: '#00ff88' }}>
                      {new Date().toLocaleTimeString()} - {realTimeData.message}
                    </Typography>
                  </Box>
                )}
                <Box sx={{ mb: 1, p: 1, backgroundColor: '#333', borderRadius: 1 }}>
                  <Typography variant="body2" sx={{ color: '#00ff88' }}>
                    15:23:45 - IBB Research: New attack vector discovered for Apache HTTP
                  </Typography>
                </Box>
                <Box sx={{ mb: 1, p: 1, backgroundColor: '#333', borderRadius: 1 }}>
                  <Typography variant="body2" sx={{ color: '#ffc107' }}>
                    15:22:12 - ML Intelligence: Anomaly detected in WordPress traffic
                  </Typography>
                </Box>
                <Box sx={{ mb: 1, p: 1, backgroundColor: '#333', borderRadius: 1 }}>
                  <Typography variant="body2" sx={{ color: '#f44336' }}>
                    15:20:33 - SAST Engine: Critical vulnerability in payment processing
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* System Health */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                System Health
              </Typography>
              <Box sx={{ mt: 2 }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                  <Typography variant="body2">Orchestration Service</Typography>
                  <Chip label="Healthy" color="success" size="small" />
                </Box>
                <LinearProgress
                  variant="determinate"
                  value={95}
                  sx={{ mb: 2, backgroundColor: '#333' }}
                />

                <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                  <Typography variant="body2">ML Intelligence</Typography>
                  <Chip label="Healthy" color="success" size="small" />
                </Box>
                <LinearProgress
                  variant="determinate"
                  value={88}
                  sx={{ mb: 2, backgroundColor: '#333' }}
                />

                <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                  <Typography variant="body2">IBB Research</Typography>
                  <Chip label="Healthy" color="success" size="small" />
                </Box>
                <LinearProgress
                  variant="determinate"
                  value={92}
                  sx={{ mb: 2, backgroundColor: '#333' }}
                />

                <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                  <Typography variant="body2">SAST/DAST Engine</Typography>
                  <Chip label="Warning" color="warning" size="small" />
                </Box>
                <LinearProgress
                  variant="determinate"
                  value={76}
                  sx={{ backgroundColor: '#333' }}
                />
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Dashboard;