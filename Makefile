NAME		=	aes.a

NAME_TEST	=	aes_test

SRC_DIR		=	./src

SRC			=	aes.cpp

SRC_TEST	=	test.cpp

OBJ			=	$(SRC:cpp=o)

OBJ_TEST	=	$(SRC_TEST:cpp=o)

CC			=	g++

CFLAGS		=	-Wall -Wextra -Werror -std=c++20

AR			=	ar rc

RM			=	rm -f

.PHONY:		all clean fclean re

all:		$(NAME)

$(OBJ):		$(SRC)
			$(CC) $(CFLAGS) -c -o $(OBJ) $(SRC)

$(OBJ_TEST):	$(SRC_TEST)
			$(CC) $(CFLAGS) -c -o $(OBJ_TEST) $(SRC_TEST)

$(NAME):	$(OBJ)
			$(CC) -c $(CFLAGS) $(SRC)
			$(AR) $(NAME) $(OBJ)

$(NAME_TEST):	$(OBJ) $(OBJ_TEST)
			$(CC) $(CFLAGS) $(OBJ_TEST) $(OBJ) -o $(NAME_TEST)

clean:
			$(RM) $(OBJ) $(OBJ_TEST)

fclean:		clean
			$(RM) $(NAME) $(NAME_TEST)

re:			fclean all

test:		$(NAME_TEST)
			./$(NAME_TEST)
