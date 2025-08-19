import { useState, useEffect } from 'react'
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import { Toaster } from '@/components/ui/sonner'
import { ThemeProvider } from '@/components/theme-provider'
import { Sidebar } from '@/components/sidebar'
import { TopBar } from '@/components/top-bar'
import { Dashboard } from '@/pages/dashboard'
import { Assessments } from '@/pages/assessments'
import { AssessmentDetail } from '@/pages/assessment-detail'
import { Recommendations } from '@/pages/recommendations'
import { Roadmaps } from '@/pages/roadmaps'
import { RoadmapDetail } from '@/pages/roadmap-detail'
import { Analytics } from '@/pages/analytics'
import { Settings } from '@/pages/settings'
import { About } from '@/pages/about'
import { ApiProvider } from '@/contexts/api-context'
import './App.css'

function App() {
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [currentUser] = useState({
    name: 'Security Administrator',
    role: 'Admin',
    avatar: null
  })

  return (
    <ThemeProvider defaultTheme="light" storageKey="adzero-theme">
      <ApiProvider>
        <Router>
          <div className="min-h-screen bg-background">
            <Toaster />
            
            {/* Sidebar */}
            <Sidebar 
              open={sidebarOpen} 
              onOpenChange={setSidebarOpen}
            />
            
            {/* Main Content */}
            <div className={`transition-all duration-300 ${
              sidebarOpen ? 'ml-64' : 'ml-16'
            }`}>
              {/* Top Bar */}
              <TopBar 
                user={currentUser}
                onMenuClick={() => setSidebarOpen(!sidebarOpen)}
              />
              
              {/* Page Content */}
              <main className="p-6">
                <Routes>
                  <Route path="/" element={<Navigate to="/dashboard" replace />} />
                  <Route path="/dashboard" element={<Dashboard />} />
                  <Route path="/assessments" element={<Assessments />} />
                  <Route path="/assessments/:id" element={<AssessmentDetail />} />
                  <Route path="/recommendations" element={<Recommendations />} />
                  <Route path="/roadmaps" element={<Roadmaps />} />
                  <Route path="/roadmaps/:id" element={<RoadmapDetail />} />
                  <Route path="/analytics" element={<Analytics />} />
                  <Route path="/settings" element={<Settings />} />
                  <Route path="/about" element={<About />} />
                </Routes>
              </main>
            </div>
          </div>
        </Router>
      </ApiProvider>
    </ThemeProvider>
  )
}

export default App

