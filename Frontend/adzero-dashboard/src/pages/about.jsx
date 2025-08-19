import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { 
  Shield, 
  Heart, 
  Github, 
  Globe, 
  Mail, 
  Award,
  Target,
  Users,
  Lock,
  CheckCircle
} from 'lucide-react'

export function About() {
  const features = [
    {
      icon: Shield,
      title: 'Comprehensive Assessment',
      description: 'Complete Active Directory security analysis with PowerShell automation'
    },
    {
      icon: Target,
      title: 'Zero Trust Roadmaps',
      description: 'Detailed implementation roadmaps for Zero Trust architecture'
    },
    {
      icon: Users,
      title: 'Identity Analysis',
      description: 'Human and non-human identity risk assessment and management'
    },
    {
      icon: Lock,
      title: 'Permission Auditing',
      description: 'Comprehensive permission and access control analysis'
    }
  ]

  const zeroTrustPrinciples = [
    'Verify Explicitly',
    'Use Least Privilege Access',
    'Assume Breach'
  ]

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="text-center space-y-4">
        <div className="flex items-center justify-center space-x-3">
          <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-primary">
            <Shield className="h-8 w-8 text-primary-foreground" />
          </div>
          <div>
            <h1 className="text-4xl font-bold tracking-tight">ADZero Trust</h1>
            <p className="text-xl text-muted-foreground">
              Active Directory Zero Trust Assessment Tool
            </p>
          </div>
        </div>
        <Badge variant="secondary" className="text-sm">
          Version 1.0
        </Badge>
      </div>

      {/* Mission Statement */}
      <Card>
        <CardHeader className="text-center">
          <CardTitle className="flex items-center justify-center space-x-2">
            <Heart className="h-5 w-5 text-red-500" />
            <span>A Community Contribution</span>
          </CardTitle>
          <CardDescription className="text-base">
            Empowering organizations to transition from traditional perimeter-based security 
            to modern Zero Trust architectures through comprehensive assessment and actionable roadmaps.
          </CardDescription>
        </CardHeader>
        <CardContent className="text-center">
          <p className="text-muted-foreground">
            This tool is created to give back to the cybersecurity community, leveraging 25+ years 
            of expertise to help organizations improve their security posture and achieve Zero Trust maturity.
          </p>
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Author Information */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Award className="h-5 w-5 text-primary" />
              <span>About the Author</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <h3 className="text-lg font-semibold">Moazzam Jafri</h3>
              <p className="text-muted-foreground">Cybersecurity Expert & Architect</p>
            </div>
            
            <div className="space-y-2">
              <div className="flex items-center space-x-2">
                <CheckCircle className="h-4 w-4 text-green-500" />
                <span className="text-sm">25+ Years in Cybersecurity</span>
              </div>
              <div className="flex items-center space-x-2">
                <CheckCircle className="h-4 w-4 text-green-500" />
                <span className="text-sm">Zero Trust Architecture Specialist</span>
              </div>
              <div className="flex items-center space-x-2">
                <CheckCircle className="h-4 w-4 text-green-500" />
                <span className="text-sm">Active Directory Security Expert</span>
              </div>
              <div className="flex items-center space-x-2">
                <CheckCircle className="h-4 w-4 text-green-500" />
                <span className="text-sm">Community Advocate</span>
              </div>
            </div>

            <Separator />

            <div className="flex space-x-2">
              <Button variant="outline" size="sm">
                <Github className="mr-2 h-4 w-4" />
                GitHub
              </Button>
              <Button variant="outline" size="sm">
                <Globe className="mr-2 h-4 w-4" />
                Website
              </Button>
              <Button variant="outline" size="sm">
                <Mail className="mr-2 h-4 w-4" />
                Contact
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Zero Trust Principles */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Target className="h-5 w-5 text-primary" />
              <span>Zero Trust Principles</span>
            </CardTitle>
            <CardDescription>
              Core principles that guide this assessment tool
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {zeroTrustPrinciples.map((principle, index) => (
              <div key={index} className="flex items-center space-x-3 p-3 border rounded-lg">
                <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary/10">
                  <span className="text-sm font-bold text-primary">{index + 1}</span>
                </div>
                <span className="font-medium">{principle}</span>
              </div>
            ))}
            
            <div className="pt-2">
              <p className="text-sm text-muted-foreground">
                These principles form the foundation of modern cybersecurity architecture, 
                moving beyond traditional perimeter-based security models.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Key Features */}
      <Card>
        <CardHeader>
          <CardTitle>Key Features</CardTitle>
          <CardDescription>
            Comprehensive capabilities for Active Directory Zero Trust assessment
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-6 md:grid-cols-2">
            {features.map((feature, index) => (
              <div key={index} className="flex items-start space-x-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                  <feature.icon className="h-5 w-5 text-primary" />
                </div>
                <div>
                  <h3 className="font-medium">{feature.title}</h3>
                  <p className="text-sm text-muted-foreground">{feature.description}</p>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Technical Information */}
      <Card>
        <CardHeader>
          <CardTitle>Technical Information</CardTitle>
          <CardDescription>
            Technology stack and implementation details
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-3">
            <div>
              <h4 className="font-medium mb-2">Backend</h4>
              <div className="space-y-1 text-sm text-muted-foreground">
                <div>Python Flask API</div>
                <div>SQLite Database</div>
                <div>PowerShell Integration</div>
              </div>
            </div>
            <div>
              <h4 className="font-medium mb-2">Frontend</h4>
              <div className="space-y-1 text-sm text-muted-foreground">
                <div>React 18</div>
                <div>Tailwind CSS</div>
                <div>Recharts Visualization</div>
              </div>
            </div>
            <div>
              <h4 className="font-medium mb-2">Assessment</h4>
              <div className="space-y-1 text-sm text-muted-foreground">
                <div>PowerShell Scripts</div>
                <div>Active Directory APIs</div>
                <div>Security Frameworks</div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* License and Contribution */}
      <Card>
        <CardHeader>
          <CardTitle>Open Source & Community</CardTitle>
          <CardDescription>
            Contributing to the cybersecurity community
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <h4 className="font-medium mb-2">License</h4>
              <p className="text-sm text-muted-foreground">
                Released under MIT License for maximum community benefit and adoption.
              </p>
            </div>
            <div>
              <h4 className="font-medium mb-2">Contributions</h4>
              <p className="text-sm text-muted-foreground">
                Community contributions, feedback, and improvements are welcome and encouraged.
              </p>
            </div>
          </div>
          
          <Separator />
          
          <div className="text-center">
            <p className="text-sm text-muted-foreground mb-4">
              "Giving back to the community that has given me so much throughout my career."
            </p>
            <p className="text-sm font-medium">- Moazzam Jafri</p>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

