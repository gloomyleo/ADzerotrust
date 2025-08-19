import { useState, useEffect } from 'react'
import { useParams } from 'react-router-dom'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { useApi } from '@/contexts/api-context'
import { Shield, ArrowLeft } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Link } from 'react-router-dom'

export function AssessmentDetail() {
  const { id } = useParams()
  const { assessmentApi } = useApi()
  const [assessment, setAssessment] = useState(null)

  useEffect(() => {
    if (id) {
      loadAssessment()
    }
  }, [id])

  const loadAssessment = async () => {
    try {
      const response = await assessmentApi.get(id)
      setAssessment(response.data)
    } catch (error) {
      console.error('Failed to load assessment:', error)
    }
  }

  if (!assessment) {
    return (
      <div className="space-y-6">
        <div className="flex items-center space-x-4">
          <Button variant="ghost" size="sm" asChild>
            <Link to="/assessments">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to Assessments
            </Link>
          </Button>
        </div>
        <Card>
          <CardContent className="flex items-center justify-center py-12">
            <div className="text-center">
              <Shield className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
              <h3 className="text-lg font-medium">Loading assessment...</h3>
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center space-x-4">
        <Button variant="ghost" size="sm" asChild>
          <Link to="/assessments">
            <ArrowLeft className="mr-2 h-4 w-4" />
            Back to Assessments
          </Link>
        </Button>
      </div>

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{assessment.name}</h1>
          <p className="text-muted-foreground">{assessment.domain}</p>
        </div>
        <Badge variant={assessment.status === 'completed' ? 'default' : 'secondary'}>
          {assessment.status}
        </Badge>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Assessment Details</CardTitle>
          <CardDescription>Detailed view of the assessment results</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <h4 className="font-medium">Assessment Type</h4>
              <p className="text-muted-foreground">{assessment.assessment_type}</p>
            </div>
            <div>
              <h4 className="font-medium">Zero Trust Score</h4>
              <p className="text-muted-foreground">{assessment.zero_trust_score || 'N/A'}%</p>
            </div>
            <div>
              <h4 className="font-medium">Total Identities</h4>
              <p className="text-muted-foreground">{assessment.total_identities || 0}</p>
            </div>
            <div>
              <h4 className="font-medium">High Risk Items</h4>
              <p className="text-muted-foreground">{assessment.high_risk_items || 0}</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

