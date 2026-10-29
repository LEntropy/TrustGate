# Build: compile, run unit tests, package three WARs.
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /src
COPY pom.xml .
COPY core core
COPY idp idp
COPY sp sp
RUN --mount=type=cache,target=/root/.m2 mvn -q -B package

# Run: Tomcat 10.1 with the IdP at /idp and the same SP WAR deployed as /portal and /mail.
FROM tomcat:10.1-jdk17-temurin
RUN rm -rf /usr/local/tomcat/webapps/* \
 && groupadd -r app && useradd -r -g app app \
 && mkdir -p /data && chown -R app:app /data /usr/local/tomcat
COPY --from=build --chown=app:app /src/idp/target/idp.war /usr/local/tomcat/webapps/idp.war
COPY --from=build --chown=app:app /src/sp/target/sp.war /usr/local/tomcat/webapps/portal.war
COPY --from=build --chown=app:app /src/sp/target/sp.war /usr/local/tomcat/webapps/mail.war
COPY --chown=app:app docker/ROOT /usr/local/tomcat/webapps/ROOT
USER app
ENV TG_DATA_DIR=/data
VOLUME /data
EXPOSE 8080
