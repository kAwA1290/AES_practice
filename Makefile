NAME		=	aes.a

NAME_TEST	=	aes_test

SRC_DIR		=	./src

SRC			=	aes.cpp

SRC_TEST	=	test.cpp

OBJ			=	$(SRC:cpp=o)

OBJ_TEST	=	$(SRC_TEST:cpp=o)

CC			=	g++

CFLAGS		=	-Wall -Wextra -Werror

AR			=	ar rc

RM			=	rm -f

.PHONY:		all clean fclean re

all:		$(NAME)

$(NAME):	$(OBJ)
			$(CC) -c $(FLAGS) $(SRC)
			$(AR) $(NAME) $(OBJ)

$(NAME_TEST):	$(OBJ) $(OBJ_TEST)
			$(CC) $(FLAGS) $(OBJ_TEST) $(OBJ) -o $(NAME_TEST)

clean:
			$(RM) $(OBJ) $(OBJ_TEST)

fclean:		clean
			$(RM) $(NAME) $(NAME_TEST)

re:			fclean all

test:		$(NAME_TEST)
			./$(NAME_TEST)
