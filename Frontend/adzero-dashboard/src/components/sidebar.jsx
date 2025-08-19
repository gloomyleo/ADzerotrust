import { useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Separator } from '@/components/ui/separator'
import { 
  LayoutDashboard,
  Shield,
  FileText,
  Map,
  BarChart3,
  Settings,
  Info,
  ChevronLeft,
  ChevronRight,
  Target,
  Users,
  Lock,
  AlertTriangle
} from 'lucide-react'

const navigationItems = [
  {
    title: 'Overview',
    items: [
      {
        title: 'Dashboard',
        href: '/dashboard',
        icon: LayoutDashboard,
        description: 'Main dashboard overview'
      }
    ]
  },
  {
    title: 'Assessment',
    items: [
      {
        title: 'Assessments',
        href: '/assessments',
        icon: Shield,
        description: 'Manage AD assessments'
      },
      {
        title: 'Recommendations',
        href: '/recommendations',
        icon: FileText,
        description: 'Security recommendations'
      }
    ]
  },
  {
    title: 'Zero Trust',
    items: [
      {
        title: 'Roadmaps',
        href: '/roadmaps',
        icon: Map,
        description: 'Implementation roadmaps'
      },
      {
        title: 'Analytics',
        href: '/analytics',
        icon: BarChart3,
        description: 'Security analytics'
      }
    ]
  },
  {
    title: 'System',
    items: [
      {
        title: 'Settings',
        href: '/settings',
        icon: Settings,
        description: 'Application settings'
      },
      {
        title: 'About',
        href: '/about',
        icon: Info,
        description: 'About ADZero Trust'
      }
    ]
  }
]

export function Sidebar({ open, onOpenChange }) {
  const location = useLocation()

  return (
    <div className={cn(
      "fixed left-0 top-0 z-40 h-screen bg-sidebar border-r border-sidebar-border transition-all duration-300",
      open ? "w-64" : "w-16"
    )}>
      <div className="flex h-full flex-col">
        {/* Header */}
        <div className="flex h-16 items-center justify-between px-4 border-b border-sidebar-border">
          {open && (
            <div className="flex items-center space-x-2">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary">
                <Shield className="h-5 w-5 text-primary-foreground" />
              </div>
              <div className="flex flex-col">
                <span className="text-sm font-semibold text-sidebar-foreground">ADZero Trust</span>
                <span className="text-xs text-sidebar-foreground/60">v1.0</span>
              </div>
            </div>
          )}
          
          <Button
            variant="ghost"
            size="sm"
            onClick={() => onOpenChange(!open)}
            className="h-8 w-8 p-0"
          >
            {open ? (
              <ChevronLeft className="h-4 w-4" />
            ) : (
              <ChevronRight className="h-4 w-4" />
            )}
          </Button>
        </div>

        {/* Navigation */}
        <ScrollArea className="flex-1 px-3 py-4">
          <nav className="space-y-6">
            {navigationItems.map((section, sectionIndex) => (
              <div key={sectionIndex}>
                {open && (
                  <h3 className="mb-2 px-3 text-xs font-semibold text-sidebar-foreground/60 uppercase tracking-wider">
                    {section.title}
                  </h3>
                )}
                
                <div className="space-y-1">
                  {section.items.map((item) => {
                    const isActive = location.pathname === item.href
                    
                    return (
                      <Link key={item.href} to={item.href}>
                        <Button
                          variant={isActive ? "secondary" : "ghost"}
                          className={cn(
                            "w-full justify-start h-10",
                            !open && "px-2",
                            isActive && "bg-sidebar-accent text-sidebar-accent-foreground"
                          )}
                          title={!open ? item.title : undefined}
                        >
                          <item.icon className={cn("h-4 w-4", open && "mr-3")} />
                          {open && (
                            <span className="flex-1 text-left">{item.title}</span>
                          )}
                        </Button>
                      </Link>
                    )
                  })}
                </div>
                
                {sectionIndex < navigationItems.length - 1 && open && (
                  <Separator className="mt-4" />
                )}
              </div>
            ))}
          </nav>
        </ScrollArea>

        {/* Footer */}
        <div className="border-t border-sidebar-border p-4">
          {open ? (
            <div className="space-y-2">
              <div className="flex items-center space-x-2 text-xs text-sidebar-foreground/60">
                <Target className="h-3 w-3" />
                <span>Zero Trust Ready</span>
              </div>
              <div className="text-xs text-sidebar-foreground/40">
                By Moazzam Jafri
              </div>
            </div>
          ) : (
            <div className="flex justify-center">
              <Target className="h-4 w-4 text-sidebar-foreground/60" />
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

