#!/bin/bash

# Wait for nginx to be ready
sleep 1

# Basic GET request for existing file
curl http://localhost:8080/index.html
sleep 0.5

# # GET request for non-existent file (404)
# curl http://localhost:8080/notfound.html
# sleep 0.5

# # HEAD request
# curl -I http://localhost:8080/index.html
# sleep 0.5

# # POST request
# curl -X POST -d "test data" http://localhost:8080/index.html
# sleep 0.5

# # Request with custom headers
# curl -H "X-Custom-Header: test" http://localhost:8080/index.html
# sleep 0.5

# # Request with different HTTP version
# curl --http1.0 http://localhost:8080/index.html
# sleep 0.5

# # Request with query parameters
# curl "http://localhost:8080/index.html?param=value"
# sleep 0.5

# # Request for directory listing attempt
# curl http://localhost:8080/
# sleep 0.5

# # Large request headers
# curl -H "X-Large-Header: $(printf 'A%.0s' {1..1000})" http://localhost:8080/index.html