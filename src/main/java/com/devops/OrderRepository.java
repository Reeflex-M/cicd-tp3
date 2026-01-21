package com.devops;

import java.util.List;

public class OrderRepository {

    public static List<Order> findAll() {
        return List.of(
            new Order(1, "Laptop", 1200.0),
            new Order(2, "Mouse", 25.0)
        );
    }
}
