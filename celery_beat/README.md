# AEGIS Celery Beat Container

## Role
Periodic scheduler — sends task messages to Redis on a fixed schedule.
Beat does **not** execute tasks — it just enqueues them by name. The worker processes them.

## Schedule (celery_beat.py)

| Schedule Name | Task | Frequency |
|---------------|------|-----------|
| `alert-sweep-every-5-min` | `tasks.alert_pipeline` | Every 5 minutes |

> More periodic tasks can be added to `celery_beat.py` as the platform grows.

## Architecture note
```
celery_beat → sends task name (string) to Redis broker
                     │
                     ▼
              aegis_redis (stores the message)
                     │
                     ▼
           aegis_celery_worker dequeues + executes
```

Beat only needs the task **name** (a string). It does NOT import task modules.
This is why `celery_beat.py` has no `include=[]` — it's not needed.

## Persistent schedule
The beat schedule state is stored at:
```
/app/celerybeat-schedule/celerybeat-schedule
```
This is mounted from the `celery_beat_data` Docker volume, so the schedule
survives container restarts.

## Adding new periodic tasks
Edit `Backend/celery_beat.py`:
```python
celery.conf.beat_schedule = {
    "my-new-task": {
        "task": "tasks.my_module",        # must match @celery.task(name=...)
        "schedule": crontab(minute="*/10"),
        "kwargs": {"param": "value"},      # optional
    },
}
```
Then rebuild: `docker compose build celery_beat && docker compose up -d celery_beat`
