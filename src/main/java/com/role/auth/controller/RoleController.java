package com.role.auth.controller;

import com.role.auth.security.service.TokenService;
import com.role.auth.security.annotation.Admin;
import com.role.auth.security.annotation.User;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class RoleController {

  private final TokenService tokenService;

  public RoleController(TokenService tokenService) {
    this.tokenService = tokenService;
  }

  @Admin
  @GetMapping("/")
  public String home() {
    return "index";
  }

  @GetMapping("/login")
  public String login() {
    return "login";
  }

  @GetMapping("/admin")
  public String admin(Model model, Authentication authentication) {
    model.addAttribute("userName", authentication.getName());
    String accessToken = tokenService.generateAccessToken(authentication.getName());
    model.addAttribute("accessToken", accessToken);
    return "admin";
  }

  @User
  @GetMapping("/user")
  public String user(Model model, Authentication authentication) {
    model.addAttribute("userName", authentication.getName());
    String accessToken = tokenService.generateAccessToken(authentication.getName());
    model.addAttribute("accessToken", accessToken);
    return "user";
  }

  @GetMapping("/error")
  public String handleError(HttpServletRequest request, Model model) {
    Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
    Object message = request.getAttribute(RequestDispatcher.ERROR_MESSAGE);

    if (status != null) {
      int statusCode = Integer.parseInt(status.toString());
      model.addAttribute("status", statusCode);
      model.addAttribute("error", HttpStatus.valueOf(statusCode).getReasonPhrase());
    }

    model.addAttribute("message", message);
    return "error";
  }
}
