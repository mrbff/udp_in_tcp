NAME			:=	udp_in_tcp

C1_NAME			:=	c1_client

C2_NAME			:=	c2_server

G1_NAME			:= g1_utot

G2_NAME			:= g2_ttou

SRCS_DIR		:=	./src/

C1_FILES		:=	c1_client.c utils.c \

C2_FILES		:=	c2_server.c utils.c list_utils.c \

G1_FILES		:= g1_utot.c utils.c \

G2_FILES		:= g2_ttou.c utils.c \

C1_SRCS			:= 	$(addprefix $(SRCS_DIR), $(C1_FILES))

C2_SRCS			:= 	$(addprefix $(SRCS_DIR), $(C2_FILES))

G1_SRCS			:= 	$(addprefix $(SRCS_DIR), $(G1_FILES))

G2_SRCS			:= 	$(addprefix $(SRCS_DIR), $(G2_FILES))

C1_OBJS			:=	$(C1_SRCS:.c=.o)

C2_OBJS         :=  $(C2_SRCS:.c=.o)

G1_OBJS			:=	$(G1_SRCS:.c=.o)

G2_OBJS         :=  $(G2_SRCS:.c=.o)

.c.o:
	@${CC} ${FLAGS} -c $< -o ${<:.c=.o} -lssl -lcrypto

CC			:=	gcc

FLAGS			:=	-Wall -Wextra -Werror -g

CLR_RMV         := \033[0m
RED                 := \033[1;31m
GREEN           := \033[1;32m
YELLOW          := \033[1;33m
BLUE            := \033[1;34m
CYAN            := \033[1;36m

RM                  := rm -f

$(NAME):		$(C1_NAME) $(C2_NAME) $(G1_NAME) $(G2_NAME)

$(C1_NAME):		$(C1_OBJS)
			@echo "$(GREEN)Compilation ${CLR_RMV}of ${YELLOW}$(C1_NAME) ${CLR_RMV}..."
			@$(CC) $(FLAGS) $(C1_OBJS) -o $(C1_NAME) -lssl -lcrypto
			@echo "$(GREEN)$(C1_NAME) created ✔️ ${CLR_RMV}"

$(C2_NAME):		$(C2_OBJS)
			@echo "$(GREEN)Compilation ${CLR_RMV}of ${YELLOW}$(C2_NAME) ${CLR_RMV}..."
			@$(CC) $(FLAGS) $(C2_OBJS) -o $(C2_NAME) -lssl -lcrypto
			@echo "$(GREEN)$(C2_NAME) created ✔️ ${CLR_RMV}"

$(G1_NAME):		$(G1_OBJS)
			@echo "$(GREEN)Compilation ${CLR_RMV}of ${YELLOW}$(G1_NAME) ${CLR_RMV}..."
			@$(CC) $(FLAGS) $(G1_OBJS) -o $(G1_NAME) -lssl -lcrypto
			@echo "$(GREEN)$(G1_NAME) created ✔️ ${CLR_RMV}"

$(G2_NAME):		$(G2_OBJS)
			@echo "$(GREEN)Compilation ${CLR_RMV}of ${YELLOW}$(G2_NAME) ${CLR_RMV}..."
			@$(CC) $(FLAGS) $(G2_OBJS) -o $(G2_NAME) -lssl -lcrypto
			@echo "$(GREEN)$(G2_NAME) created ✔️ ${CLR_RMV}"

all:			$(NAME)

clean:
				@ ${RM} *.o */*.o */*/*.o
				@ echo "$(RED)Deleting $(CYAN)$(NAME) $(CLR_RMV)objs ✔️"

fclean:			clean
				@ $(RM) $(C1_NAME) $(C2_NAME) $(G1_NAME) $(G2_NAME)
				@ echo "$(RED)Deleting $(CYAN)$(NAME) $(CLR_RMV)binaries ✔️"

re:				fclean all

.PHONY:			all clean fclean re