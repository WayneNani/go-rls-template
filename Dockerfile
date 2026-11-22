# syntax=docker/dockerfile:1
# Base images pinned by digest; Renovate updates them.

FROM node:24-alpine@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5 AS web
WORKDIR /src
COPY frontend/package.json frontend/pnpm-lock.yaml frontend/pnpm-workspace.yaml frontend/
# pnpm at the version in package.json (packageManager), the single place it is pinned.
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable && cd frontend && pnpm install --frozen-lockfile
COPY frontend frontend
RUN mkdir -p internal/web/dist && cd frontend && pnpm build

FROM golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS go
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/internal/web/dist internal/web/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/migrate ./cmd/migrate

# No shell, no package manager, non-root.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:06c3c14b7fa252d9f4285242d2d665ce3b51f74b02d3c529464f220f2912aecb
COPY --from=go /out/ /app/
ENV LISTEN_ADDR=:8080
EXPOSE 8080
ENTRYPOINT ["/app/server"]
