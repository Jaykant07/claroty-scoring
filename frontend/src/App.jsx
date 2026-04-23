import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import AssetExplorer from './pages/AssetExplorer';
import AssetDetail from './pages/AssetDetail';
import ZoneView from './pages/ZoneView';
import Vulnerabilities from './pages/Vulnerabilities';
import ComplianceDashboard from './pages/ComplianceDashboard';
import Login from './pages/Login';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route element={<Layout />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/assets" element={<AssetExplorer />} />
          <Route path="/assets/:id" element={<AssetDetail />} />
          <Route path="/zones" element={<ZoneView />} />
          <Route path="/vulnerabilities" element={<Vulnerabilities />} />
          <Route path="/compliance" element={<ComplianceDashboard />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;
