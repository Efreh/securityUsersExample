package com.efr.securityUsersExample.exceptions;

import lombok.Getter;
import lombok.Setter;

import java.util.Map;

@Getter
@Setter
public class ErrorResponse {
    private String error;
    private String message;
    private Map<String,String> fieldErrors;

    public ErrorResponse(String error, String message) {
        this.error = error;
        this.message = message;
    }
}
