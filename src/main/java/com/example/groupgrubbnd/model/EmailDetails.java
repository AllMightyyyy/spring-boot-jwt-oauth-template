package com.example.groupgrubbnd.model;

import lombok.Data;

@Data
public class EmailDetails {
    private String recipient;
    private String subject;
    private String body;
}
