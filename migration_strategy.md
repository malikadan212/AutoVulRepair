# Migration Strategy: File Storage → Database-First Architecture

## Overview
This document outlines the step-by-step migration from file-based storage to database-first architecture without breaking the existing system.

## Migration Phases

### Phase 1: Database Schema & Models ✅ COMPLETED
- [x] Created new database tables (`migrations/001_create_scan_tables.sql`)
- [x] Created new SQLAlchemy models (`src/models/scan_v2.py`)
- [x] Tables created alongside existing file system

### Phase 2: Repository Layer ✅ COMPLETED
- [x] Created data access layer (`src/repositories/scan_repository.py`)
- [x] Repository can work with both file system and database
- [x] Backward compatibility maintained

### Phase 3: Service Layer ✅ COMPLETED
- [x] Created service layer (`src/services/scan_service.py`)
- [x] Business logic abstracted from storage implementation
- [x] Can switch between file and database storage

### Phase 4: API Migration ✅ COMPLETED
- [x] Created new API endpoints (`src/api/v2_routes.py`)
- [x] New endpoints use service layer
- [x] Old endpoints remain functional

### Phase 5: Background Worker ✅ COMPLETED
- [x] Created Celery-based background job processor (`src/workers/job_worker.py`)
- [x] Async processing for long-running tasks
- [x] Proper error handling and retry logic

## Phase 6: Configuration & Dependencies (Week 6)

### 6.1 Update Requirements
Add new dependencies to `requirements.txt`:

```txt
# Background job processing
celery==5.3.4
redis==5.0.1

# Database improvements
alembic==1.12.1
psycopg2-binary==2.9.9

# Monitoring and logging
structlog==23.2.0
prometheus-client==0.19.0
```

### 6.2 Environment Configuration
Update `.env` with new settings:

```env
# Redis for Celery
REDIS_URL=redis://localhost:6379/0

# Database connection pool
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=30
DATABASE_POOL_TIMEOUT=30

# Background job settings
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0

# Migration settings
ENABLE_V2_API=true
ENABLE_BACKGROUND_JOBS=true
MIGRATION_MODE=dual  # dual, database_only, file_only
```

### 6.3 Docker Compose Updates
Update `docker-compose.yml` to include Redis and worker services:

```yaml
services:
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    command: redis-server --appendonly yes

  celery-worker:
    build: .
    command: celery -A src.workers.job_worker worker --loglevel=info --queues=scan_queue,fuzzing_queue
    depends_on:
      - postgres
      - redis
    environment:
      - DATABASE_URL=${DATABASE_URL}
      - REDIS_URL=${REDIS_URL}
    volumes:
      - ./scans:/app/scans  # Temporary during migration

  celery-beat:
    build: .
    command: celery -A src.workers.job_worker beat --loglevel=info
    depends_on:
      - postgres
      - redis
    environment:
      - DATABASE_URL=${DATABASE_URL}
      - REDIS_URL=${REDIS_URL}

volumes:
  redis_data:
```

## Phase 7: Gradual Migration (Week 7)

### 7.1 Dual Mode Operation
Configure the system to run in dual mode:
- New scans use database storage
- Old scans remain in file system
- Both systems work simultaneously

### 7.2 Data Migration Script
Create script to migrate existing file-based scans to database:

```python
# scripts/migrate_file_to_db.py
def migrate_scan_files_to_database():
    """Migrate existing scan files to database"""
    scans_dir = os.getenv('SCANS_DIR', './scans')
    
    for scan_folder in os.listdir(scans_dir):
        scan_path = os.path.join(scans_dir, scan_folder)
        if os.path.isdir(scan_path):
            migrate_single_scan(scan_folder, scan_path)
```

### 7.3 Testing Strategy
- Run both old and new APIs in parallel
- Compare results between file and database storage
- Monitor performance and error rates
- Gradual traffic shifting (10% → 50% → 100%)

## Phase 8: Full Migration (Week 8)

### 8.1 Switch to Database-Only Mode
```env
MIGRATION_MODE=database_only
ENABLE_FILE_STORAGE=false
```

### 8.2 Update Main Application
Modify `app.py` to use new v2 routes:

```python
# Import new routes
from src.api.v2_routes import v2_bp

# Register new blueprint
app.register_blueprint(v2_bp, url_prefix='/api/v2')

# Redirect old routes to new ones (optional)
@app.route('/api/scan', methods=['POST'])
def scan_redirect():
    return redirect('/api/v2/scans', code=301)
```

### 8.3 Cleanup Old Code
- Remove file-based storage code
- Clean up old scan directories
- Update documentation

## Phase 9: Performance Optimization (Week 9)

### 9.1 Database Optimization
- Add proper indexes
- Optimize queries
- Set up connection pooling
- Configure read replicas if needed

### 9.2 Caching Layer
- Implement Redis caching for frequently accessed data
- Cache scan results and status
- Cache user sessions and preferences

### 9.3 Monitoring
- Set up Prometheus metrics
- Configure alerting
- Monitor database performance
- Track job queue health

## Rollback Strategy

If issues occur during migration:

### Immediate Rollback
```env
MIGRATION_MODE=file_only
ENABLE_V2_API=false
ENABLE_BACKGROUND_JOBS=false
```

### Gradual Rollback
1. Stop new scans from using database
2. Continue processing existing database scans
3. Switch back to file storage for new scans
4. Investigate and fix issues
5. Resume migration when ready

## Success Metrics

### Performance Improvements
- **Scan creation time**: < 100ms (vs current ~2s)
- **Status check time**: < 50ms (vs current ~500ms)
- **Concurrent scans**: 100+ (vs current ~10)
- **Storage efficiency**: 90% reduction in disk usage

### Reliability Improvements
- **Error rate**: < 0.1% (vs current ~5%)
- **Data consistency**: 100% (vs current ~95%)
- **Recovery time**: < 1 minute (vs current ~10 minutes)

### Scalability Improvements
- **Horizontal scaling**: Support for multiple workers
- **Database scaling**: Support for read replicas
- **Queue processing**: 1000+ jobs/minute

## Risk Mitigation

### Data Loss Prevention
- Dual storage during migration
- Regular database backups
- File system backups until migration complete
- Automated data validation

### Performance Monitoring
- Real-time metrics dashboard
- Automated alerting
- Performance regression detection
- Capacity planning

### Rollback Preparation
- Automated rollback scripts
- Health check endpoints
- Circuit breaker patterns
- Graceful degradation

## Timeline Summary

| Week | Phase | Status | Key Deliverables |
|------|-------|--------|------------------|
| 1 | Database Schema | ✅ Complete | Tables, Models |
| 2 | Repository Layer | ✅ Complete | Data Access Layer |
| 3 | Service Layer | ✅ Complete | Business Logic |
| 4 | API Migration | ✅ Complete | New Endpoints |
| 5 | Background Worker | ✅ Complete | Async Processing |
| 6 | Configuration | 🔄 In Progress | Dependencies, Config |
| 7 | Gradual Migration | ⏳ Pending | Dual Mode, Testing |
| 8 | Full Migration | ⏳ Pending | Database-Only Mode |
| 9 | Optimization | ⏳ Pending | Performance, Monitoring |

## Next Steps

1. **Install Redis** and update Docker Compose
2. **Run database migrations** to create new tables
3. **Test v2 APIs** with new database storage
4. **Configure Celery workers** for background processing
5. **Start gradual migration** of existing scan data

This migration strategy ensures zero downtime and provides multiple rollback points if issues arise.