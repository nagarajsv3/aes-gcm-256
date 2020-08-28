package com.nsv.jsmbaba.aesgcm;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
public class Person {

    private String name;

    @ToString.Exclude
    private String ssn;

    @ToString.Exclude
    private String cardNumber;

    public Person() {
    }

    public Person(String name, String ssn, String cardNumber) {
        this.name = name;
        this.ssn = ssn;
        this.cardNumber = cardNumber;
    }
}
