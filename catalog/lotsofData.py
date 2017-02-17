from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Category, Base, Item, User

engine = create_engine('sqlite:///catalog.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# Create dummy user
User1 = User(name="Robo Barista", email="tinnyTim@udacity.com",
             picture='https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png')
session.add(User1)
session.commit()

# Menu for UrbanBurger
category1 = Category(user_id=1, name="Urban Burger")

session.add(category1)
session.commit()

item2 = Item(user_id=1, name="Veggie Burger", description="Juicy grilled veggie patty with tomato mayo and lettuce",
             category=category1)

session.add(item2)
session.commit()


item1 = Item(user_id=1, name="French Fries", description="with garlic and parmesan",
             category=category1)

session.add(item1)
session.commit()

item2 = Item(user_id=1, name="Chicken Burger", description="Juicy grilled chicken patty with tomato mayo and lettuce",
             category=category1)

session.add(item2)
session.commit()

item3 = Item(user_id=1, name="Chocolate Cake", description="fresh baked and served with ice cream",
             category=category1)

session.add(item3)
session.commit()

item4 = Item(user_id=1, name="Sirloin Burger", description="Made with grade A beef",
             category=category1)

session.add(item4)
session.commit()

item5 = Item(user_id=1, name="Root Beer", description="16oz of refreshing goodness",
             category=category1)

session.add(item5)
session.commit()

item6 = Item(user_id=1, name="Iced Tea", description="with Lemon",
             category=category1)

session.add(item6)
session.commit()

item7 = Item(user_id=1, name="Grilled Cheese Sandwich",
             description="On texas toast with American Cheese", category=category1)

session.add(item7)
session.commit()


# Menu for Super Stir Fry
category2 = Category(user_id=1, name="Super Stir Fry")

session.add(category2)
session.commit()


item1 = Item(user_id=1, name="Chicken Stir Fry", description="With your choice of noodles vegetables and sauces",
             category=category2)

session.add(item1)
session.commit()

item2 = Item(user_id=1, name="Peking Duck",
             description=" A famous duck dish from Beijing[1] that has been prepared since the imperial era. The meat is prized for its thin, crisp skin, with authentic versions of the dish serving mostly the skin and little meat, sliced in front of the diners by the cook", category=category2)

session.add(item2)
session.commit()

item3 = Item(user_id=1, name="Spicy Tuna Roll", description="Seared rare ahi, avocado, edamame, cucumber with wasabi soy sauce ",
             category=category2)

session.add(item3)
session.commit()

item4 = Item(user_id=1, name="Nepali Momo ", description="Steamed dumplings made with vegetables, spices and meat. ",
             category=category2)

session.add(item4)
session.commit()

item5 = Item(user_id=1, name="Beef Noodle Soup", description="A Chinese noodle soup made of stewed or red braised beef, beef broth, vegetables and Chinese noodles.",
             category=category2)

session.add(item5)
session.commit()

item6 = Item(user_id=1, name="Ramen", description="a Japanese noodle soup dish. It consists of Chinese-style wheat noodles served in a meat- or (occasionally) fish-based broth, often flavored with soy sauce or miso, and uses toppings such as sliced pork, dried seaweed, kamaboko, and green onions.",
             category=category2)

session.add(item6)
session.commit()


# Menu for Panda Garden
category1 = Category(user_id=1, name="Panda Garden")

session.add(category1)
session.commit()


item1 = Item(user_id=1, name="Pho", description="a Vietnamese noodle soup consisting of broth, linguine-shaped rice noodles called banh pho, a few herbs, and meat.",
             category=category1)

session.add(item1)
session.commit()

item2 = Item(user_id=1, name="Chinese Dumplings", description="a common Chinese dumpling which generally consists of minced meat and finely chopped vegetables wrapped into a piece of dough skin. The skin can be either thin and elastic or thicker.",
             category=category1)

session.add(item2)
session.commit()

item3 = Item(user_id=1, name="Gyoza", description="light seasoning of Japanese gyoza with salt and soy sauce, and in a thin gyoza wrapper",
             category=category1)

session.add(item3)
session.commit()

item4 = Item(user_id=1, name="Stinky Tofu", description="Taiwanese dish, deep fried fermented tofu served with pickled cabbage.",
             category=category1)

session.add(item4)
session.commit()

item2 = Item(user_id=1, name="Veggie Burger", description="Juicy grilled veggie patty with tomato mayo and lettuce",
             category=category1)

session.add(item2)
session.commit()


# Menu for Thyme for that
category1 = Category(user_id=1, name="Thyme for That Vegetarian Cuisine ")

session.add(category1)
session.commit()


item1 = Item(user_id=1, name="Tres Leches Cake", description="Rich, luscious sponge cake soaked in sweet milk and topped with vanilla bean whipped cream and strawberries.",
             category=category1)

session.add(item1)
session.commit()

item2 = Item(user_id=1, name="Mushroom risotto", description="Portabello mushrooms in a creamy risotto",
             category=category1)

session.add(item2)
session.commit()

item3 = Item(user_id=1, name="Honey Boba Shaved Snow",
             description="Milk snow layered with honey boba, jasmine tea jelly, grass jelly, caramel, cream, and freshly made mochi", category=category1)

session.add(item3)
session.commit()

item4 = Item(user_id=1, name="Cauliflower Manchurian", description="Golden fried cauliflower florets in a midly spiced soya,garlic sauce cooked with fresh cilantro, celery, chilies,ginger & green onions",
             category=category1)

session.add(item4)
session.commit()

item5 = Item(user_id=1, name="Aloo Gobi Burrito", description="Vegan goodness. Burrito filled with rice, garbanzo beans, curry sauce, potatoes (aloo), fried cauliflower (gobi) and chutney. Nom Nom",
             category=category1)

session.add(item5)
session.commit()

item2 = Item(user_id=1, name="Veggie Burger", description="Juicy grilled veggie patty with tomato mayo and lettuce",
             category=category1)

session.add(item2)
session.commit()


# Menu for Tony's Bistro
category1 = Category(user_id=1, name="Tony\'s Bistro ")

session.add(category1)
session.commit()


item1 = Item(user_id=1, name="Shellfish Tower", description="Lobster, shrimp, sea snails, crawfish, stacked into a delicious tower",
             category=category1)

session.add(item1)
session.commit()

item2 = Item(user_id=1, name="Chicken and Rice", description="Chicken... and rice",
             category=category1)

session.add(item2)
session.commit()

item3 = Item(user_id=1, name="Mom's Spaghetti", description="Spaghetti with some incredible tomato sauce made by mom",
             category=category1)

session.add(item3)
session.commit()

item4 = Item(user_id=1, name="Choc Full O\' Mint (Smitten\'s Fresh Mint Chip ice cream)",
             description="Milk, cream, salt, ..., Liquid nitrogen magic", category=category1)

session.add(item4)
session.commit()

item5 = Item(user_id=1, name="Tonkatsu Ramen", description="Noodles in a delicious pork-based broth with a soft-boiled egg",
             category=category1)

session.add(item5)
session.commit()


# Menu for Andala's
category1 = Category(user_id=1, name="Andala\'s")

session.add(category1)
session.commit()


item1 = Item(user_id=1, name="Lamb Curry", description="Slow cook that thang in a pool of tomatoes, onions and alllll those tasty Indian spices. Mmmm.",
             category=category1)

session.add(item1)
session.commit()

item2 = Item(user_id=1, name="Chicken Marsala", description="Chicken cooked in Marsala wine sauce with mushrooms",
             category=category1)

session.add(item2)
session.commit()

item3 = Item(user_id=1, name="Potstickers", description="Delicious chicken and veggies encapsulated in fried dough.",
             category=category1)

session.add(item3)
session.commit()

item4 = Item(user_id=1, name="Nigiri Sampler", description="Maguro, Sake, Hamachi, Unagi, Uni, TORO!",
             category=category1)

session.add(item4)
session.commit()

item2 = Item(user_id=1, name="Veggie Burger", description="Juicy grilled veggie patty with tomato mayo and lettuce",
             category=category1)

session.add(item2)
session.commit()


# Menu for Auntie Ann's
category1 = Category(user_id=1, name="Auntie Ann\'s Diner' ")

session.add(category1)
session.commit()

item9 = Item(user_id=1, name="Chicken Fried Steak",
             description="Fresh battered sirloin steak fried and smothered with cream gravy", category=category1)

session.add(item9)
session.commit()


item1 = Item(user_id=1, name="Boysenberry Sorbet", description="An unsettlingly huge amount of ripe berries turned into frozen (and seedless) awesomeness",
             category=category1)

session.add(item1)
session.commit()

item2 = Item(user_id=1, name="Broiled salmon", description="Salmon fillet marinated with fresh herbs and broiled hot & fast",
             category=category1)

session.add(item2)
session.commit()

item3 = Item(user_id=1, name="Morels on toast (seasonal)",
             description="Wild morel mushrooms fried in butter, served on herbed toast slices", category=category1)

session.add(item3)
session.commit()

item4 = Item(user_id=1, name="Tandoori Chicken", description="Chicken marinated in yoghurt and seasoned with a spicy mix(chilli, tamarind among others) and slow cooked in a cylindrical clay or metal oven which gets its heat from burning charcoal.",
             category=category1)

session.add(item4)
session.commit()

item2 = Item(user_id=1, name="Veggie Burger", description="Juicy grilled veggie patty with tomato mayo and lettuce",
             category=category1)

session.add(item2)
session.commit()

item10 = Item(user_id=1, name="Spinach Ice Cream", description="vanilla ice cream made with organic spinach leaves",
              category=category1)

session.add(item10)
session.commit()


# Menu for Cocina Y Amor
category1 = Category(user_id=1, name="Cocina Y Amor ")

session.add(category1)
session.commit()


item1 = Item(user_id=1, name="Super Burrito Al Pastor",
             description="Marinated Pork, Rice, Beans, Avocado, Cilantro, Salsa, Tortilla", category=category1)

session.add(item1)
session.commit()

item2 = Item(user_id=1, name="Cachapa", description="Golden brown, corn-based Venezuelan pancake; usually stuffed with queso telita or queso de mano, and possibly lechon. ",
             category=category1)

session.add(item2)
session.commit()


category1 = Category(user_id=1, name="State Bird Provisions")
session.add(category1)
session.commit()

item1 = Item(user_id=1, name="Chantrelle Toast", description="Crispy Toast with Sesame Seeds slathered with buttery chantrelle mushrooms",
             category=category1)

session.add(item1)
session.commit

item1 = Item(user_id=1, name="Guanciale Chawanmushi",
             description="Japanese egg custard served hot with spicey Italian Pork Jowl (guanciale)", category=category1)

session.add(item1)
session.commit()


item1 = Item(user_id=1, name="Lemon Curd Ice Cream Sandwich",
             description="Lemon Curd Ice Cream Sandwich on a chocolate macaron with cardamom meringue and cashews", category=category1)

session.add(item1)
session.commit()


print "added menu items!"
