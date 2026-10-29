package com.trustgate.core.db;

import java.sql.SQLException;

public class DataAccessException extends RuntimeException {
    public DataAccessException(SQLException cause) {
        super(cause.getMessage(), cause);
    }
}
