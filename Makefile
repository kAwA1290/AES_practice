NAME		=	aes

SRC_DIR		=	./src

SRC			=	aes.cpp

OBJ			=	$(SRC:cpp=o)

CC			=	g++

CFLAGS		=	-Wall -Wextra -Werror

RM			=	rm -f

.PHONY:		all clean fclean re

all:		$(NAME)

$(NAME):	$(OBJ)
			$(CC) $(FLAGS) $(OBJ) -o $(NAME)

clean:
			$(RM) $(OBJ) $(OBJ_SERVER)

fclean:		clean
			$(RM) $(NAME)

re:			fclean all

run:		all
			./aes
