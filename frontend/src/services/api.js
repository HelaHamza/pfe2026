import axios from 'axios'

const api = axios.create({
  baseURL: '/',
  headers: { 'Content-Type': 'application/json' },
})

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

export const authService = {
  login:       (email, password) => api.post('/auth/login',        { email, password }).then(r => r.data),
  signup:      (data)            => api.post('/auth/signup',       data).then(r => r.data),
  createAdmin: ()                => api.post('/auth/create-admin').then(r => r.data),
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

export default api