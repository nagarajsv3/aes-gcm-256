package com.nsv.jsmbaba.aesgcm;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.Gson;

public class JsonUtils {

    private JsonUtils(){}

    public static String getJsonMessageFromObject(Person jsmbaba) {
        Gson gson = new Gson();
        return gson.toJson(jsmbaba);
    }
}
