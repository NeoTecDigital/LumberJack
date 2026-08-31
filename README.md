# LumberJack API Documentation
![lumberjack500](https://github.com/user-attachments/assets/1f1c2f9e-a550-47eb-8f18-a11abbc1cf58)
## Overview
The LumberJack API provides a hierarchical event tracking system where nodes can have multiple parents and events can be tracked across different organizational paths.

## Installation & Usage

### Using as a Package
```bash
go get github.com/vaziolabs/lumberjack
```

### Building from Source
```bash
git clone https://github.com/vaziolabs/lumberjack.git
cd lumberjack
go build
```

### Getting Started
Starting LumberJack is as simple as running the following command:
```bash
./lumberjack
```

To create a new server configuration:
```bash
./lumberjack create
```

To start the server:
```bash
./lumberjack start

# Or with dashboard
./lumberjack start -d
```

To list current configuration:
```bash
./lumberjack list
```

To delete configuration:
```bash
./lumberjack delete
```

## TODOS:
 - [ ] Improved Testing
    - [ ] Fix Testing Logging and Scoping to create Run directives
    - [ ] Remove redundant tests
    - [ ] Finish incomplete tests
 - [X] Refactor CLI types to work with the Core for directory structure
    - [X] Ensure logger is logging to the correct file
    - [X] Ensure the dat file is created and updated in the correct directory
    - [X] Move cli types to top level
 - [X] Add Core Logger
    - [X] Integrate debug logging into log file
 - [ ] Improve CLI
   - [X] Allow Multiple Databases and configs
   - [X] Add proper linux directory structure
   - [ ] Ensure delete commands require admin confirmation
   - [X] Update `list` command to use the proper ID
   - [X] Fix `delete` command to not delete all databases
   - [X] Test ALL commands
   - [ ] Test all Help commands
   - [X] have CLI daemonize API and Dashboard
   - [X] Remove Admin from Config
   - [ ] Add Windows Support
 - [ ] Test Dashboard Data Display and Interaction
    - [ ] Improve Top Bar integration
    - [ ] Add User Profile and Server Settings (if permissioned)
    - [X] Add Dashboard Login
    - [ ] Add API Event Logging
    - [ ] Add Node Level User Access Scoping
    - [ ] LogOut
    - [ ] MFA
    - [ ] Third Party Integration (Slack, Google Calendar, etc.)
 - [ ] Create Typescript module for direct API integration
 - [ ] Security
    - [ ] Add TLS
    - [ ] Improve Session Authentication for Database & Dashboard
    - [ ] Remove Session Token from frontend Cookie 
    - [ ] Remove Sensitive Data from logs
    - [X] Add JWT
    - [ ] Integrate for Certificate Authentication
    - [ ] Add Session Expiration
    - [ ] Add Session Refresh
  - [ ] Refactor
  - [ ] Create Proper Documentation

## Core Concepts

### Nodes
- **Branch Node**: Can contain other nodes
- **Leaf Node**: End points for tracking events
- Each node can have multiple parents, enabling flexible organizational structures

### Events
An Event represents a tracked activity with start/end times and associated entries.

#### Attributes:
- `StartTime`: When the event begins
- `EndTime`: When the event concludes
- `Entries`: List of timestamped records
- `Metadata`: Custom event data
- `Status`: pending/ongoing/finished

### Entries
Timestamped records within an event.

#### Attributes:
- `Timestamp`: Creation time
- `Content`: Entry data
- `Metadata`: Additional entry info
- `UserID`: Creator identifier

## API Endpoints

### Authentication

#### Login
```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "password"
  }'
```

### Authentication Response
```json
{
  "session_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

### Attachments

#### Upload Attachment
```bash
curl -X POST http://localhost:8080/attachments/upload \
  -H "Authorization: Bearer <token>" \
  -F "file=@/path/to/file.jpg" \
  -F "path=work/projects/project-alpha"
```

#### Get Attachment
```bash
curl -X GET http://localhost:8080/attachments/{id} \
  -H "Authorization: Bearer <token>" \
  -G --data-urlencode "path=work/projects/project-alpha"
```

#### Delete Attachment
```bash
curl -X DELETE http://localhost:8080/attachments/{id} \
  -H "Authorization: Bearer <token>" \
  -G --data-urlencode "path=work/projects/project-alpha"
```

#### Add Entry Attachment
```bash
curl -X POST http://localhost:8080/events/{eventId}/entries/{entryIndex}/attachments \
  -H "Authorization: Bearer <token>" \
  -F "file=@/path/to/file.jpg" \
  -F "path=work/projects/project-alpha"
```

### Attachment Response
```json
{
  "id": "att-123",
  "name": "document.pdf",
  "type": "application/pdf",
  "size": 1048576,
  "hash": "sha256-hash",
  "uploaded_by": "user-123",
  "uploaded_at": "2024-01-15T10:30:00Z"
}
```

### Node Management

#### Create Node
Events are tracked on leaves, so a client creates the leaf it is going to track on. Missing
ancestors are created as branches, `type` defaults to `leaf`, and creating the same path twice
returns the same node.
```bash
curl -X POST http://localhost:8080/nodes \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "path": "work/projects/project-alpha",
    "type": "leaf"
  }'
```

### Create Node Response
```json
{
  "id": "user-1786229776411046621",
  "name": "project-alpha",
  "path": "work/projects/project-alpha",
  "type": "leaf"
}
```

#### Get Forest
```bash
curl -X GET http://localhost:8080/forest \
  -H "Authorization: Bearer <token>"
```

#### Get Tree
```bash
curl -X GET http://localhost:8080/forest/tree \
  -H "Authorization: Bearer <token>"
```

#### Assign User
```bash
curl -X POST http://localhost:8080/users/assign \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "path": "work/projects/project-alpha",
    "assignee_id": "user123",
    "permission": "write"
  }'
```

### Event Management

#### Start Event
```bash
curl -X POST http://localhost:8080/events/start \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "path": "work/projects/project-alpha",
    "event_id": "sprint-1",
    "metadata": {
      "type": "sprint",
      "duration": "2 weeks"
    }
  }'
```

#### Plan Event
```bash
curl -X POST http://localhost:8080/events/plan \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "path": "work/projects/project-alpha",
    "event_id": "sprint-2",
    "start_time": "2024-01-15T09:00:00Z",
    "end_time": "2024-01-29T17:00:00Z",
    "metadata": {
      "type": "sprint"
    }
  }'
```

#### Append to Event
```bash
curl -X POST http://localhost:8080/events/append \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "path": "work/projects/project-alpha",
    "event_id": "sprint-1",
    "content": "Completed user authentication feature",
    "metadata": {
      "type": "milestone"
    }
  }'
```

#### End Event
```bash
curl -X POST http://localhost:8080/events/end \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "path": "work/projects/project-alpha",
    "event_id": "sprint-1"
  }'
```

### Time Tracking

#### Start Time Tracking
```bash
curl -X POST http://localhost:8080/time/start \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "path": "work/projects/project-alpha"
  }'
```

#### Stop Time Tracking
```bash
curl -X POST http://localhost:8080/time/stop \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "path": "work/projects/project-alpha"
  }'
```

#### Get Time Tracking
```bash
curl -X GET http://localhost:8080/time \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "path": "work/projects/project-alpha"
  }'
```

### User Management

#### Create User

Administrative. Requires a session belonging to a user with Admin permission on the root of the
forest — there is no self-registration: an anonymous caller is refused with 401, and a
non-administrative session with 403.

```bash
curl -X POST http://localhost:8080/users/create \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin token>" \
  -d '{
    "username": "john_doe",
    "email": "john@example.com",
    "password": "secure_password"
  }'
```

#### Get Users
```bash
curl -X GET http://localhost:8080/users \
  -H "Authorization: Bearer <token>"
```

#### Get User Profile
```bash
curl -X GET http://localhost:8080/users/profile \
  -H "Authorization: Bearer <token>"
```

### Settings

#### Get Server Settings
```bash
curl -X GET http://localhost:8080/settings/ \
  -H "Authorization: Bearer <token>"
```

#### Update Server Settings
```bash
curl -X POST http://localhost:8080/settings/update \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "organization": "MyOrg",
    "server_port": "8080",
    "dashboard_url": "http://localhost:3000"
  }'
```

## Response Formats

### Event Summary Response
```json
{
  "event_id": "sprint-1",
  "status": "finished",
  "start_time": "2024-01-01T09:00:00Z",
  "end_time": "2024-01-14T17:00:00Z",
  "entries_count": 15,
  "metadata": {
    "type": "sprint",
    "team": "alpha"
  }
}
```

### Time Tracking Summary Response
```json
[
  {
    "start_time": "2024-01-04T09:00:00Z",
    "end_time": "2024-01-04T17:00:00Z",
    "duration": 28800000000000
  }
]
```

## Error Handling
All endpoints return standard HTTP status codes:
- 200: Success
- 400: Bad Request
- 401: Unauthorized
- 403: Forbidden
- 404: Not Found
- 500: Internal Server Error

Error responses include a message:
```json
{
  "error": "Invalid event ID format"
}
```
