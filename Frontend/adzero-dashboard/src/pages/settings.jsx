import { Card, CardContent } from '@/components/ui/card'
import { Settings as SettingsIcon } from 'lucide-react'

export function Settings() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Settings</h1>
        <p className="text-muted-foreground">Application settings and configuration</p>
      </div>
      <Card>
        <CardContent className="flex items-center justify-center py-12">
          <div className="text-center">
            <SettingsIcon className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
            <h3 className="text-lg font-medium">Settings</h3>
            <p className="text-muted-foreground">This page is under development</p>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

