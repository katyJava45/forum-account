package telran.java45.security.filter;

import java.io.IOException;
import java.util.Base64;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import telran.java45.accounting.dao.UserAccountRepository;
import telran.java45.accounting.model.UserAccount;

@Component
@RequiredArgsConstructor
@Order(30)
public class LoginFilter implements Filter {

	final UserAccountRepository userAccountRepository;
	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		if(checkEndPoint(request.getMethod(), request.getServletPath())) {
			String[] user = request.getServletPath().split("/");
			UserAccount userAccount = userAccountRepository.findById(request.getUserPrincipal().getName()).get();
			if(!userAccount.getLogin().equals(user[3])) {
				response.sendError(403, "not owner");
			}
		}

		chain.doFilter(request, response);
	}
	
	private boolean checkEndPoint(String method, String path) {
		return ("PUT".equalsIgnoreCase(method) && path.matches("/account/user/\\w+/?"));
	}


}
