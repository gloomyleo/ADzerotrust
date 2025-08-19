import { Card, CardContent } from '@/components/ui/card'
import { Map } from 'lucide-react'

export function Roadmaps() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Roadmaps</h1>
        <p className="text-muted-foreground">Zero Trust implementation roadmaps</p>
      </div>
      <Card>
        <CardContent className="flex items-center justify-center py-12">
          <div className="text-center">
            <Map className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
            <h3 className="text-lg font-medium">Roadmaps</h3>
            <p className="text-muted-foreground">This page is under development</p>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

