NAME		=	aes

NAME_TEST	=	aes_test

SRC_DIR		=	./src

SRC			=	aes.cpp

SRC_TEST	=	test.cpp

OBJ			=	$(SRC:cpp=o)

OBJ_TEST	=	$(SRC_TEST:cpp=o)

CC			=	clang++

CFLAGS		=	-Wall -Wextra -Werror -g

RM			=	rm -f

.PHONY:		all clean fclean re

all:		$(NAME)

$(NAME):	$(OBJ)
			$(CC) $(FLAGS) $(OBJ) -o $(NAME)

$(NAME_TEST):	$(OBJ) $(OBJ_TEST)
			$(CC) $(FLAGS) $(OBJ_TEST) $(OBJ) -o $(NAME_TEST)

clean:
			$(RM) $(OBJ) $(OBJ_SERVER)

fclean:		clean
			$(RM) $(NAME) $(NAME_TEST)

re:			fclean all

#run:		all
#			./aes | less

debug:		$(NAME_TEST)
			lldb ./aes_test

test:		$(NAME_TEST)
			./$(NAME_TEST)
