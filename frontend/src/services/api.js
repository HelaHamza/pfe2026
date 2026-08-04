import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  headers: { 'Content-Type': 'application/json' },
})
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

export const authService = {
  login:     (email, password) => api.post('/auth/login',      { email, password }).then(r => r.data),
  verifyOtp: (email, code)     => api.post('/auth/verify-otp', { email, code }).then(r => r.data), // ← nouveau
  signup:    (data)            => api.post('/auth/signup',     data).then(r => r.data),

  requestPasswordReset: (email) =>
    api.post('/auth/forgot-password', { email }).then(r => r.data),
  confirmPasswordReset: (token, newPassword) =>
    api.post('/auth/reset-password', { token, new_password: newPassword }).then(r => r.data),
}

export const profileService = {
  getMe:    ()     => api.get('/profile/me').then(r => r.data),
  updateMe: (data) => api.patch('/profile/me', data).then(r => r.data),
}

export const adminService = {
  getPendingUsers: ()              => api.get('/admin/users/pending').then(r => r.data),
  getAllUsers:     ()              => api.get('/admin/users').then(r => r.data),
  approveUser:    (email, action) => api.post('/admin/users/approve', { email, action }).then(r => r.data),
}

export const feedbackService = {
  submit:          (message, rating) => api.post('/feedback/',        { message, rating }).then(r => r.data),
  getApproved:     ()                => api.get('/feedback/approved').then(r => r.data),
  getAll:          ()                => api.get('/feedback/all').then(r => r.data),
  action:          (feedback_id, action) => api.post('/feedback/action', { feedback_id, action }).then(r => r.data),
}

export const dashboardService = {
  getDashboard:    ()             => api.get('/dashboard').then(r => r.data),
  getResults:      (limit = 500)  => api.get('/results', { params: { limit } }).then(r => r.data),
  getResultDetail: (type, id)     => api.get(`/results/${type}/${id}`).then(r => r.data),
  launchAnalysis:  ()             => api.post('/analyse/run').then(r => r.data),
}

export const aiDashboardService = {
  frozenModel:    () => api.get('/ai-dashboard/frozen-model').then(r => r.data),
  overview:       () => api.get('/ai-dashboard/overview').then(r => r.data),
  retraining:     () => api.get('/ai-dashboard/retraining').then(r => r.data),
  triage:         () => api.get('/ai-dashboard/triage').then(r => r.data),
  evalComparison: () => api.get('/ai-dashboard/eval-comparison').then(r => r.data),
  pending: (params = {}) =>
    api.get('/ai-dashboard/pending', { params }).then(r => r.data),
}

export default api