package com.efr.securityUsersExample.exceptions;

public class UserWithNameExistsException extends RuntimeException{
    public UserWithNameExistsException(String message) {
        super(message);
    }
}
