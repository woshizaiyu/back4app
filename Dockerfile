FROM eclipse-temurin:17-jre-alpine

WORKDIR /app

RUN apk add --no-cache curl

COPY target/server.jar app.jar

ENV TOKEN="" \
    HOST="" \
    FEED_PATH="feed" \
    LABEL="" \
    CHANNEL_PATH="" \
    SERVER_PORT=3000 \
    DEBUG="false"

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${SERVER_PORT}/ || exit 1

CMD ["java", "-jar", "app.jar"]
