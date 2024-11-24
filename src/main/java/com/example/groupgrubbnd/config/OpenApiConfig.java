package com.example.groupgrubbnd.config;

import io.swagger.v3.oas.models.*;
import io.swagger.v3.oas.models.info.*;
import org.springdoc.core.GroupedOpenApi;
import org.springframework.context.annotation.*;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("GroupGrubbnd API")
                        .version("1.0")
                        .description("API documentation for GroupGrubbnd application")
                        .license(new License().name("Apache 2.0").url("http://springdoc.org")));
    }

    @Bean
    public GroupedOpenApi publicApi() {
        return GroupedOpenApi.builder()
                .group("groupgrubbnd-public")
                .pathsToMatch("/api/**")
                .build();
    }
}
