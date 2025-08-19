import { Card, CardContent } from '@/components/ui/card'
import { BarChart3 } from 'lucide-react'

export function Analytics() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Analytics</h1>
        <p className="text-muted-foreground">Security analytics and insights</p>
      </div>
      <Card>
        <CardContent className="flex items-center justify-center py-12">
          <div className="text-center">
            <BarChart3 className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
            <h3 className="text-lg font-medium">Analytics</h3>
            <p className="text-muted-foreground">This page is under development</p>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

