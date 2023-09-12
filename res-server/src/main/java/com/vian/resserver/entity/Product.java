package com.vian.resserver.entity;

import lombok.Data;

import java.util.Date;
import java.util.UUID;

/**
 * Represents a product
 */
@Data
public class Product {

    private String id;
    private String name;
    private String description;
    private float price;
    private String currency;

    public static Product from(String name, String description, float price, String currency) {
        Product product = new Product();
        product.setName(name);
        product.setDescription(description);
        product.setPrice(price);
        product.setCurrency(currency);

        product.setId(UUID.randomUUID().toString());
        return product;
    }

}