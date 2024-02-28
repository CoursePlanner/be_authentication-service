FROM eclipse-temurin:21-jdk-jammy
RUN useradd -m cpuser
RUN chown -R cpuser:cpuser /home/cpuser
COPY target/cp_app.jar /home/cpuser/cp_app.jar
USER cpuser
ENTRYPOINT [ "java", "-jar", "/home/cpuser/cp_app.jar" ]
EXPOSE 9001