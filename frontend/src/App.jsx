import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider } from './context/AuthContext'
import ProtectedRoute    from './components/ProtectedRoute.jsx'
import LoginPage         from './pages/LoginPage.jsx'
import SignUpPage        from './pages/SignUpPage.jsx'
import HomePage          from './pages/HomePage.jsx'
import DashboardPage     from './pages/DashboardPage.jsx'
import ProfilePage       from './pages/ProfilePage.jsx'
import PendingUsersPage  from './pages/PendingUsersPage.jsx'
import ApprovedUsersPage from './pages/ApprovedUsersPage.jsx'
import FeedbacksPage     from './pages/FeedbacksPage.jsx'
import AiDashboardPage from './pages/AiDashboardPage'

//import Dashboard from "./pages/dashboard.jsx";

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
  <Route path="/login"  element={<LoginPage />} />
  <Route path="/signup" element={<SignUpPage />} />
  <Route path="/home"      element={<ProtectedRoute><HomePage /></ProtectedRoute>} />
  <Route path="/dashboard" element={<ProtectedRoute><DashboardPage /></ProtectedRoute>} />
  <Route path="/profile"   element={<ProtectedRoute><ProfilePage /></ProtectedRoute>} />
  <Route path="/admin/pending"   element={<ProtectedRoute><PendingUsersPage /></ProtectedRoute>} />
  <Route path="/admin/users"     element={<ProtectedRoute><ApprovedUsersPage /></ProtectedRoute>} />
  <Route path="/admin/feedbacks" element={<ProtectedRoute><FeedbacksPage /></ProtectedRoute>} />
  <Route path="/ai-dashboard"    element={<ProtectedRoute><AiDashboardPage /></ProtectedRoute>} />
  <Route path="*" element={<Navigate to="/login" replace />} />
</Routes>
      </BrowserRouter>
    </AuthProvider>
  )
}