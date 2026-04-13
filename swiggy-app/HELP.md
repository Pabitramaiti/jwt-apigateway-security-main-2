# Read Me First
The following was discovered as part of building this project:

* The JVM level was changed from '1.8' to '17', review the [JDK Version Range](https://github.com/spring-projects/spring-framework/wiki/Spring-Framework-Versions#jdk-version-range) on the wiki for more details.

# Getting Started

### Reference Documentation
For further reference, please consider the following sections:

* [Official Apache Maven documentation](https://maven.apache.org/guides/index.html)
* [Spring Boot Maven Plugin Reference Guide](https://docs.spring.io/spring-boot/docs/3.0.4/maven-plugin/reference/html/)
* [Create an OCI image](https://docs.spring.io/spring-boot/docs/3.0.4/maven-plugin/reference/html/#build-image)
* [Spring Web](https://docs.spring.io/spring-boot/docs/3.0.4/reference/htmlsingle/#web)
* [Eureka Discovery Client](https://docs.spring.io/spring-cloud-netflix/docs/current/reference/html/#service-discovery-eureka-clients)

### Guides
The following guides illustrate how to use some features concretely:

* [Building a RESTful Web Service](https://spring.io/guides/gs/rest-service/)
* [Serving Web Content with Spring MVC](https://spring.io/guides/gs/serving-web-content/)
* [Building REST services with Spring](https://spring.io/guides/tutorials/rest/)
* [Service Registration and Discovery with Eureka and Spring Cloud](https://spring.io/guides/gs/service-registration-and-discovery/)

### Insert data into usercredential table

insert into usercredential values (3,'sagar.chahan@gmail.com','Sagar Chahan','sagar');
insert into usercredential values (1,'pabitram.mail@gmail.com','Pabitra Maiti','Asmita@14');
insert into usercredential values (2,'asmita.maiti@gmail.com','Asmita Maiti','Asmita@2014');
insert into usercredential values (4,'ravi.varma@gmail.com','Ravi Varma','Ravi@varma');

### Swiggy-App Direct Endpoint url
GET: http://localhost:8081/swiggy/home
GET: http://localhost:8081/swiggy/35fds631
  --header 'loggedInUser: sagar'

### Restaurant-App Endpoint url (Data are hard coded in RestaurantOrderDAO.java)
GET: http://localhost:8082/restaurant/home
GET: http://localhost:8082/restaurant/orders/status/35fds631
