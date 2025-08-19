import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { 
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Progress } from '@/components/ui/progress'
import { useApi } from '@/contexts/api-context'
import { 
  Plus, 
  Search, 
  Filter,
  Shield,
  Clock,
  CheckCircle,
  AlertCircle,
  Play,
  Eye
} from 'lucide-react'

export function Assessments() {
  const { assessmentApi, loading } = useApi()
  const [assessments, setAssessments] = useState([])
  const [filteredAssessments, setFilteredAssessments] = useState([])
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')

  useEffect(() => {
    loadAssessments()
  }, [])

  useEffect(() => {
    filterAssessments()
  }, [assessments, searchTerm, statusFilter])

  const loadAssessments = async () => {
    try {
      const response = await assessmentApi.getAll()
      setAssessments(response.data || [])
    } catch (error) {
      console.error('Failed to load assessments:', error)
    }
  }

  const filterAssessments = () => {
    let filtered = assessments

    if (searchTerm) {
      filtered = filtered.filter(assessment => 
        assessment.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        assessment.domain.toLowerCase().includes(searchTerm.toLowerCase())
      )
    }

    if (statusFilter !== 'all') {
      filtered = filtered.filter(assessment => assessment.status === statusFilter)
    }

    setFilteredAssessments(filtered)
  }

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="h-4 w-4 text-green-500" />
      case 'running':
        return <Play className="h-4 w-4 text-blue-500" />
      case 'failed':
        return <AlertCircle className="h-4 w-4 text-red-500" />
      default:
        return <Clock className="h-4 w-4 text-gray-500" />
    }
  }

  const getStatusBadge = (status) => {
    const variants = {
      completed: 'default',
      running: 'secondary',
      failed: 'destructive',
      pending: 'outline'
    }
    return <Badge variant={variants[status] || 'outline'}>{status}</Badge>
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Assessments</h1>
          <p className="text-muted-foreground">
            Manage Active Directory Zero Trust assessments
          </p>
        </div>
        <Button asChild>
          <Link to="/assessments/new">
            <Plus className="mr-2 h-4 w-4" />
            New Assessment
          </Link>
        </Button>
      </div>

      {/* Filters */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Filter Assessments</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col sm:flex-row gap-4">
            <div className="flex-1">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search by name or domain..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-[180px]">
                <Filter className="mr-2 h-4 w-4" />
                <SelectValue placeholder="Filter by status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="pending">Pending</SelectItem>
                <SelectItem value="running">Running</SelectItem>
                <SelectItem value="completed">Completed</SelectItem>
                <SelectItem value="failed">Failed</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Assessments Grid */}
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
        {filteredAssessments.map((assessment) => (
          <Card key={assessment.id} className="hover:shadow-lg transition-shadow">
            <CardHeader>
              <div className="flex items-start justify-between">
                <div className="flex items-center space-x-2">
                  <Shield className="h-5 w-5 text-primary" />
                  <div>
                    <CardTitle className="text-lg">{assessment.name}</CardTitle>
                    <CardDescription>{assessment.domain}</CardDescription>
                  </div>
                </div>
                {getStatusIcon(assessment.status)}
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Status:</span>
                {getStatusBadge(assessment.status)}
              </div>

              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Type:</span>
                <Badge variant="outline">{assessment.assessment_type}</Badge>
              </div>

              {assessment.zero_trust_score > 0 && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium">Zero Trust Score:</span>
                    <span className="text-sm font-bold">{assessment.zero_trust_score}%</span>
                  </div>
                  <Progress value={assessment.zero_trust_score} />
                </div>
              )}

              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-muted-foreground">Identities:</span>
                  <div className="font-medium">{assessment.total_identities || 0}</div>
                </div>
                <div>
                  <span className="text-muted-foreground">High Risks:</span>
                  <div className="font-medium text-red-600">{assessment.high_risk_items || 0}</div>
                </div>
              </div>

              <div className="text-xs text-muted-foreground">
                Created: {new Date(assessment.created_at).toLocaleDateString()}
                {assessment.completed_at && (
                  <> • Completed: {new Date(assessment.completed_at).toLocaleDateString()}</>
                )}
              </div>

              <div className="flex space-x-2">
                <Button variant="outline" size="sm" asChild className="flex-1">
                  <Link to={`/assessments/${assessment.id}`}>
                    <Eye className="mr-2 h-4 w-4" />
                    View
                  </Link>
                </Button>
                {assessment.status === 'pending' && (
                  <Button size="sm" className="flex-1">
                    <Play className="mr-2 h-4 w-4" />
                    Run
                  </Button>
                )}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Empty State */}
      {filteredAssessments.length === 0 && !loading && (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Shield className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-medium mb-2">No assessments found</h3>
            <p className="text-muted-foreground text-center mb-4">
              {searchTerm || statusFilter !== 'all' 
                ? 'Try adjusting your search or filter criteria.'
                : 'Get started by creating your first Active Directory assessment.'
              }
            </p>
            {!searchTerm && statusFilter === 'all' && (
              <Button asChild>
                <Link to="/assessments/new">
                  <Plus className="mr-2 h-4 w-4" />
                  Create First Assessment
                </Link>
              </Button>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}

