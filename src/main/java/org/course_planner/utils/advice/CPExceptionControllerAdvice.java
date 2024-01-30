package org.course_planner.utils.advice;

import org.course_planner.utils.dto.ExceptionResponseDTO;
import org.course_planner.utils.exceptions.*;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@ControllerAdvice
public class CPExceptionControllerAdvice extends ResponseEntityExceptionHandler {
    @ExceptionHandler(value = {AuthenticationException.class})
    protected ResponseEntity<ExceptionResponseDTO> handleAuthenticationException(AuthenticationException ex) {
        ExceptionResponseDTO responseDTO = new ExceptionResponseDTO(ex);
        return new ResponseEntity<>(responseDTO, responseDTO.getStatus());
    }

    @ExceptionHandler(value = {MessageException.class})
    protected ResponseEntity<ExceptionResponseDTO> handleMessageException(MessageException ex) {
        ExceptionResponseDTO responseDTO = new ExceptionResponseDTO(ex);
        return new ResponseEntity<>(responseDTO, responseDTO.getStatus());
    }

    @ExceptionHandler(value = {PrerequisiteFailureException.class})
    protected ResponseEntity<ExceptionResponseDTO> handlePrerequisiteFailureException(PrerequisiteFailureException ex) {
        ExceptionResponseDTO responseDTO = new ExceptionResponseDTO(ex);
        return new ResponseEntity<>(responseDTO, responseDTO.getStatus());
    }

    @ExceptionHandler(value = {PropertyNotFoundException.class})
    protected ResponseEntity<ExceptionResponseDTO> handlePropertyNotFoundException(PropertyNotFoundException ex) {
        ExceptionResponseDTO responseDTO = new ExceptionResponseDTO(ex);
        return new ResponseEntity<>(responseDTO, responseDTO.getStatus());
    }

    @ExceptionHandler(value = {UserException.class})
    protected ResponseEntity<ExceptionResponseDTO> handleUserException(UserException ex) {
        ExceptionResponseDTO responseDTO = new ExceptionResponseDTO(ex);
        return new ResponseEntity<>(responseDTO, responseDTO.getStatus());
    }

    @ExceptionHandler(value = {APIExecutionException.class})
    protected ResponseEntity<ExceptionResponseDTO> handleAPIExecutionException(APIExecutionException ex) {
        ExceptionResponseDTO responseDTO = new ExceptionResponseDTO(ex);
        return new ResponseEntity<>(responseDTO, responseDTO.getStatus());
    }
}
