import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Skeleton } from '@/components/ui/skeleton'
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
  Area,
  AreaChart
} from 'recharts'
import { useApi } from '@/contexts/api-context'
import { 
  Shield, 
  Users, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  TrendingUp,
  Target,
  FileText,
  Map,
  Activity,
  Plus
} from 'lucide-react'

const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884D8']

export function Dashboard() {
  const { dashboardApi, loading } = useApi()
  const [overview, setOverview] = useState(null)
  const [recentAssessments, setRecentAssessments] = useState([])
  const [trends, setTrends] = useState(null)
  const [topRisks, setTopRisks] = useState([])
  const [recommendations, setRecommendations] = useState(null)

  useEffect(() => {
    loadDashboardData()
  }, [])

  const loadDashboardData = async () => {
    try {
      const [overviewData, assessmentsData, trendsData, risksData, recsData] = await Promise.all([
        dashboardApi.getOverview(),
        dashboardApi.getRecentAssessments(5),
        dashboardApi.getTrends(30),
        dashboardApi.getTopRisks({ limit: 10 }),
        dashboardApi.getPriorityRecommendations({ limit: 20 })
      ])

      setOverview(overviewData.data)
      setRecentAssessments(assessmentsData.data)
      setTrends(trendsData.data)
      setTopRisks(risksData.data)
      setRecommendations(recsData.data)
    } catch (error) {
      console.error('Failed to load dashboard data:', error)
    }
  }

  const getMaturityColor = (level) => {
    switch (level?.toLowerCase()) {
      case 'advanced': return 'bg-green-500'
      case 'intermediate': return 'bg-blue-500'
      case 'initial': return 'bg-yellow-500'
      case 'traditional': return 'bg-red-500'
      default: return 'bg-gray-500'
    }
  }

  const getRiskColor = (level) => {
    switch (level?.toLowerCase()) {
      case 'high': return 'text-red-600'
      case 'medium': return 'text-yellow-600'
      case 'low': return 'text-green-600'
      default: return 'text-gray-600'
    }
  }

  if (loading && !overview) {
    return (
      <div className="space-y-6">
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {[...Array(4)].map((_, i) => (
            <Card key={i}>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <Skeleton className="h-4 w-[100px]" />
                <Skeleton className="h-4 w-4" />
              </CardHeader>
              <CardContent>
                <Skeleton className="h-8 w-[60px] mb-2" />
                <Skeleton className="h-3 w-[120px]" />
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
          <p className="text-muted-foreground">
            Active Directory Zero Trust Assessment Overview
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Button asChild>
            <Link to="/assessments">
              <Plus className="mr-2 h-4 w-4" />
              New Assessment
            </Link>
          </Button>
        </div>
      </div>

      {/* Overview Cards */}
      {overview && (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Assessments</CardTitle>
              <Shield className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{overview.assessments.total}</div>
              <p className="text-xs text-muted-foreground">
                {overview.assessments.completion_rate.toFixed(1)}% completion rate
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Zero Trust Score</CardTitle>
              <Target className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{overview.zero_trust.average_score}%</div>
              <Progress value={overview.zero_trust.average_score} className="mt-2" />
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Critical Issues</CardTitle>
              <AlertTriangle className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-red-600">
                {overview.recommendations.critical}
              </div>
              <p className="text-xs text-muted-foreground">
                {overview.recommendations.high} high priority
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Risks</CardTitle>
              <Activity className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {overview.risks.identity_risks.total + overview.risks.permission_risks.total}
              </div>
              <p className="text-xs text-muted-foreground">
                {overview.risks.identity_risks.high + overview.risks.permission_risks.high} high risk
              </p>
            </CardContent>
          </Card>
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Recent Assessments */}
        <Card>
          <CardHeader>
            <CardTitle>Recent Assessments</CardTitle>
            <CardDescription>
              Latest assessment activities and their status
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {recentAssessments.length > 0 ? (
                recentAssessments.map((assessment) => (
                  <div key={assessment.id} className="flex items-center justify-between p-3 border rounded-lg">
                    <div className="flex-1">
                      <div className="flex items-center space-x-2">
                        <h4 className="font-medium">{assessment.name}</h4>
                        <Badge variant={assessment.status === 'completed' ? 'default' : 
                                      assessment.status === 'running' ? 'secondary' : 'outline'}>
                          {assessment.status}
                        </Badge>
                      </div>
                      <p className="text-sm text-muted-foreground">{assessment.domain}</p>
                      <div className="flex items-center space-x-4 mt-2">
                        <div className="flex items-center space-x-1">
                          <Progress 
                            value={assessment.module_progress?.percentage || 0} 
                            className="w-20 h-2" 
                          />
                          <span className="text-xs text-muted-foreground">
                            {assessment.module_progress?.percentage?.toFixed(0) || 0}%
                          </span>
                        </div>
                        {assessment.critical_recommendations > 0 && (
                          <Badge variant="destructive" className="text-xs">
                            {assessment.critical_recommendations} Critical
                          </Badge>
                        )}
                      </div>
                    </div>
                    <Button variant="ghost" size="sm" asChild>
                      <Link to={`/assessments/${assessment.id}`}>
                        View
                      </Link>
                    </Button>
                  </div>
                ))
              ) : (
                <div className="text-center py-6">
                  <Shield className="mx-auto h-12 w-12 text-muted-foreground" />
                  <h3 className="mt-2 text-sm font-medium">No assessments yet</h3>
                  <p className="mt-1 text-sm text-muted-foreground">
                    Get started by creating your first assessment.
                  </p>
                  <Button className="mt-4" asChild>
                    <Link to="/assessments">
                      <Plus className="mr-2 h-4 w-4" />
                      Create Assessment
                    </Link>
                  </Button>
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Zero Trust Maturity Distribution */}
        {overview && (
          <Card>
            <CardHeader>
              <CardTitle>Zero Trust Maturity</CardTitle>
              <CardDescription>
                Distribution of maturity levels across assessments
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {Object.entries(overview.zero_trust.maturity_distribution).map(([level, count]) => (
                  <div key={level} className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <div className={`w-3 h-3 rounded-full ${getMaturityColor(level)}`} />
                      <span className="font-medium capitalize">{level}</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className="text-sm text-muted-foreground">{count}</span>
                      <div className="w-20">
                        <Progress 
                          value={(count / overview.assessments.total) * 100} 
                          className="h-2" 
                        />
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
      </div>

      {/* Charts Section */}
      {trends && (
        <div className="grid gap-6 lg:grid-cols-2">
          {/* Assessment Trends */}
          <Card>
            <CardHeader>
              <CardTitle>Assessment Trends</CardTitle>
              <CardDescription>
                Number of assessments created over time
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={trends.assessments}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="date" />
                  <YAxis />
                  <Tooltip />
                  <Area 
                    type="monotone" 
                    dataKey="count" 
                    stroke="#8884d8" 
                    fill="#8884d8" 
                    fillOpacity={0.3}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          {/* Zero Trust Score Trends */}
          <Card>
            <CardHeader>
              <CardTitle>Zero Trust Score Trends</CardTitle>
              <CardDescription>
                Average Zero Trust scores over time
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={trends.zero_trust_scores}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="date" />
                  <YAxis domain={[0, 100]} />
                  <Tooltip />
                  <Line 
                    type="monotone" 
                    dataKey="average_score" 
                    stroke="#00C49F" 
                    strokeWidth={2}
                  />
                </LineChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Top Risks and Priority Recommendations */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* Top Risks */}
        <Card>
          <CardHeader>
            <CardTitle>Top Security Risks</CardTitle>
            <CardDescription>
              Highest priority risks requiring immediate attention
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {topRisks.slice(0, 5).map((risk, index) => (
                <div key={risk.id} className="flex items-start space-x-3 p-3 border rounded-lg">
                  <div className="flex-shrink-0">
                    <Badge variant="outline" className="text-xs">
                      #{index + 1}
                    </Badge>
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center space-x-2">
                      <h4 className="text-sm font-medium truncate">
                        {risk.type === 'identity' ? risk.identity_name : risk.resource_path}
                      </h4>
                      <Badge variant={risk.risk_level === 'High' ? 'destructive' : 'secondary'}>
                        {risk.risk_level}
                      </Badge>
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">
                      {risk.assessment_name} • {risk.domain}
                    </p>
                    <div className="flex items-center space-x-2 mt-2">
                      <span className="text-xs font-medium">Risk Score:</span>
                      <span className={`text-xs font-bold ${getRiskColor(risk.risk_level)}`}>
                        {risk.risk_score}
                      </span>
                    </div>
                  </div>
                </div>
              ))}
              
              {topRisks.length === 0 && (
                <div className="text-center py-6">
                  <CheckCircle className="mx-auto h-12 w-12 text-green-500" />
                  <h3 className="mt-2 text-sm font-medium">No high-risk items</h3>
                  <p className="mt-1 text-sm text-muted-foreground">
                    Great! No critical risks detected.
                  </p>
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Priority Recommendations */}
        <Card>
          <CardHeader>
            <CardTitle>Priority Recommendations</CardTitle>
            <CardDescription>
              Critical and high-priority security recommendations
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {recommendations && (
                <>
                  {recommendations.Critical?.slice(0, 3).map((rec) => (
                    <Alert key={rec.id} className="border-red-200">
                      <AlertTriangle className="h-4 w-4 text-red-600" />
                      <AlertTitle className="text-sm">Critical: {rec.category}</AlertTitle>
                      <AlertDescription className="text-xs">
                        {rec.recommendation.substring(0, 100)}...
                      </AlertDescription>
                    </Alert>
                  ))}
                  
                  {recommendations.High?.slice(0, 2).map((rec) => (
                    <Alert key={rec.id} className="border-yellow-200">
                      <Clock className="h-4 w-4 text-yellow-600" />
                      <AlertTitle className="text-sm">High: {rec.category}</AlertTitle>
                      <AlertDescription className="text-xs">
                        {rec.recommendation.substring(0, 100)}...
                      </AlertDescription>
                    </Alert>
                  ))}
                </>
              )}
              
              <div className="pt-2">
                <Button variant="outline" size="sm" asChild className="w-full">
                  <Link to="/recommendations">
                    <FileText className="mr-2 h-4 w-4" />
                    View All Recommendations
                  </Link>
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Quick Actions */}
      <Card>
        <CardHeader>
          <CardTitle>Quick Actions</CardTitle>
          <CardDescription>
            Common tasks and shortcuts
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-3">
            <Button variant="outline" asChild className="h-20 flex-col">
              <Link to="/assessments">
                <Shield className="h-6 w-6 mb-2" />
                <span>New Assessment</span>
              </Link>
            </Button>
            
            <Button variant="outline" asChild className="h-20 flex-col">
              <Link to="/roadmaps">
                <Map className="h-6 w-6 mb-2" />
                <span>View Roadmaps</span>
              </Link>
            </Button>
            
            <Button variant="outline" asChild className="h-20 flex-col">
              <Link to="/analytics">
                <TrendingUp className="h-6 w-6 mb-2" />
                <span>Analytics</span>
              </Link>
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

