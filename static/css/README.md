# AutoVulRepair CSS Architecture

## File Organization

### `main.css` - Core Application Styles
Contains all fundamental styling that applies across the entire application:
- CSS variables for colors, spacing, transitions
- Global element styles (body, cards, buttons)
- Common component patterns (stat cards, badges, alerts)
- Utility classes
- Responsive breakpoints

**When to use**: Import this in every page via layout.html (already done)

### `components.css` - Reusable UI Components
Contains specific, reusable component styles:
- Progress trackers
- Vulnerability cards
- Timelines
- Empty states
- Notification toasts
- Filter bars

**When to use**: Import this in every page via layout.html (already done)

### Module-Specific CSS (Coming in Step 2)
Will contain styles specific to individual modules:
- `modules/dashboard.css` - Dashboard-specific styles
- `modules/scan.css` - Scan page styles
- `modules/fuzzing.css` - Fuzzing module styles
- `modules/monitoring.css` - Monitoring dashboard styles

**When to use**: Import only on pages that need them using `{% block extra_css %}`

## CSS Variable Reference

### Colors
```css
--primary-color: #667eea
--success-color: #28a745
--danger-color: #dc3545
--warning-color: #ffc107
--info-color: #17a2b8
--secondary-color: #6c757d
```

### Spacing
```css
--border-radius: 10px
--border-radius-sm: 5px
--border-radius-lg: 15px
--card-padding: 1.5rem
```

### Effects
```css
--transition-speed: 0.2s
--shadow-sm: 0 2px 4px rgba(0,0,0,0.1)
--shadow-md: 0 4px 8px rgba(0,0,0,0.15)
--shadow-lg: 0 8px 16px rgba(0,0,0,0.2)
```

## Usage Examples

### Using CSS Variables in Your Styles
```css
.my-custom-button {
  background-color: var(--primary-color);
  border-radius: var(--border-radius);
  transition: all var(--transition-speed);
}
```

### Using Predefined Classes
```html
<!-- Stat Card -->
<div class="stat-card">
  <div class="stat-value success">42</div>
  <div class="stat-label">Vulnerabilities Fixed</div>
</div>

<!-- Status Badge -->
<span class="status-badge status-completed">Completed</span>

<!-- Vulnerability Card -->
<div class="vulnerability-card severity-high">
  <div class="vulnerability-header">
    <h6 class="vulnerability-title">Buffer Overflow</h6>
    <span class="badge bg-danger">High</span>
  </div>
  <div class="vulnerability-description">
    Description here...
  </div>
</div>
```

## Best Practices

1. **Use CSS Variables**: Always use variables for colors and spacing
2. **Reuse Classes**: Check if a class exists before creating new styles
3. **Mobile First**: Design for mobile, enhance for desktop
4. **Consistent Naming**: Use BEM-like naming (block__element--modifier)
5. **Avoid !important**: Structure CSS to avoid specificity wars

## Migration Guide

### Before (Inline Styles)
```html
<div style="background: white; padding: 1.5rem; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
  Content
</div>
```

### After (Using Classes)
```html
<div class="stat-card">
  Content
</div>
```

### Before (Embedded Style Block)
```html
<style>
.my-card {
  background: white;
  padding: 1.5rem;
  border-radius: 10px;
}
</style>
```

### After (Using Existing Classes or Variables)
```css
/* In module-specific CSS file */
.my-card {
  background: white;
  padding: var(--card-padding);
  border-radius: var(--border-radius);
}
```
