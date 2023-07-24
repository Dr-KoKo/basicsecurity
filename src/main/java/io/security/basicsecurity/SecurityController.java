package io.security.basicsecurity;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.SessionAttribute;

@RestController
public class SecurityController {
    @GetMapping("/")
    public String index() {
        return "home";
    }

    @GetMapping("/loginPage")
    public String loginPage() {
        return "loginPage";
    }

    @GetMapping("/user")
    public String user() {
        return "user";
    }

    @GetMapping("/admin/pay")
    public String adminPay() {
        return "adminPay";
    }

    @GetMapping("/admin/**")
    public String admin() {
        return "admin";
    }

    @GetMapping("/denied")
    public String denied() {
        return "Access is denied";
    }

    @GetMapping("/test/getAuthentication")
    public String index(@SessionAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY) SecurityContext auth1,
                        @AuthenticationPrincipal User auth2
    ) {
        Authentication auth3 = SecurityContextHolder.getContext().getAuthentication();

        System.out.println(auth1.getAuthentication().getPrincipal());
        System.out.println(auth2);
        System.out.println(auth3.getPrincipal());

        return "home";
    }

    @GetMapping("/test/getAuthentication/subThread")
    public String thread() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

                System.out.println(authentication.getPrincipal());
            }
        }
        ).start();

        return "thread";
    }
}
